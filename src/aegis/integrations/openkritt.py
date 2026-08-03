"""open·kritt interop — arm's-length, over its finding export only.

`open·kritt <https://github.com/Kritt-ai/open-kritt>`_ is a separate, self-hosted
AI security-research platform. It is licensed **AGPL-3.0**, so its source is *not*
vendored into Aegis: doing so would place all of Aegis under the AGPL (including its
network-source-disclosure clause). Instead Aegis treats open·kritt as an external
service and exchanges only its public data contract:

* **inbound** — :func:`ingest_openkritt_findings` maps an open·kritt finding export
  (its ``vulnerabilities`` rows, each a ``json_answer`` with the eight required keys
  plus dedupe/rank wrapper fields) into Aegis :class:`~aegis.model.Candidate`
  objects, so open·kritt results flow through the *same* triage/verification and
  reporting pipeline as every native detector;
* **outbound** — :func:`to_openkritt_output_format` emits an open·kritt-compatible
  step ``output_format`` so Aegis can hand it a focused research task and get a
  finding shaped for ingest back.

Two boundaries are kept deliberately:

1. **Candidate, not verdict.** An imported row is an unverified hypothesis
   (``evidence_id is None``); open·kritt's own ``exploitable``/rank is a hint, not
   proof. It still must pass Aegis's verification gate to be reported.
2. **No exploit payloads surfaced.** The ``malicious_input_example`` key (a live
   payload) is never copied into the surfaced candidate — it stays in open·kritt for
   human review, honoring Aegis's no-auto-exploitation boundary.

Operating open·kritt is the operator's responsibility, including its own AGPL
network-source obligations.
"""

from __future__ import annotations

import json
import os

from aegis.model import Candidate

#: The eight keys open·kritt requires in a terminal step's ``json_answer``.
OPENKRITT_FINDING_KEYS = (
    "explanation", "file_path", "line", "malicious_input_example",
    "summary", "trigger_flow", "vulnerability_type", "malicious_actor",
)

# vulnerability_type keyword -> CWE. First hit wins; unknown types still surface.
_CWE_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("reentran",), "CWE-841"),
    (("overflow", "underflow", "arithmetic"), "CWE-190"),
    (("unchecked", "return value", "low-level call"), "CWE-252"),
    (("selfdestruct", "self-destruct", "delegatecall", "tx.origin",
      "access control", "unprotected", "missing auth", "unauthor", "privileg"), "CWE-284"),
    (("idor", "bola", "object reference", "object-level"), "CWE-639"),
    (("bfla", "function level", "function-level"), "CWE-285"),
    (("ssrf", "server-side request"), "CWE-918"),
    (("price", "oracle", "manipulat", "rounding", "slippage"), "CWE-682"),
    (("signature", "replay", "ecrecover"), "CWE-347"),
    (("sql", "injection"), "CWE-89"),
    (("xss", "cross-site scripting"), "CWE-79"),
    (("path travers", "directory travers"), "CWE-22"),
)

_IMPACT_WEIGHT = {"critical": 0.95, "high": 0.8, "medium": 0.55, "low": 0.3, "info": 0.2}
_IMPACT_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def ingest_openkritt_findings(
    export, *, only_canonical: bool = True, min_impact: str | None = None,
) -> list[Candidate]:
    """Map an open·kritt finding export into unverified Aegis candidates.

    ``export`` may be a list of vulnerability records, a wrapper dict (``results`` /
    ``vulnerabilities`` / ``findings``), a JSON string, or a path to a JSON file.
    ``only_canonical`` drops rows open·kritt already clustered as duplicates so its
    dedup is respected; ``min_impact`` filters below a severity floor
    (``"low"``..``"critical"``).
    """
    floor = _IMPACT_RANK.get((min_impact or "").lower()) if min_impact else None
    out: list[Candidate] = []
    for rec in _records(export):
        if not isinstance(rec, dict):
            continue
        answer = rec.get("json_answer") or rec.get("jsonAnswer")
        if not isinstance(answer, dict) or not answer:
            answer = rec                        # serialized API shape flattens the keys
        if not answer.get("file_path") and not answer.get("summary") and not answer.get("vulnerability_type"):
            continue
        # Respect open·kritt's own dedup: an explicit non-canonical row is a
        # duplicate of a canonical one we'll also see. Rows with no verdict are kept.
        if only_canonical and _canonical(rec) is False:
            continue

        vtype = str(answer.get("vulnerability_type")
                    or rec.get("vulnerability_type") or "").strip()
        impact = _impact_level(rec, answer)
        if floor is not None and _IMPACT_RANK.get(impact, 2) < floor:
            continue

        file_path = str(answer.get("file_path") or "")
        conf = _confidence(rec, answer)
        out.append(Candidate(
            asset=_asset_for(file_path, rec),
            action="passive_discovery",           # static review over source; read-only
            worker="integration:openkritt",
            code_location=_loc(file_path, answer.get("line")),
            observed=_trim(f"{vtype}: {answer.get('summary', '')}".strip(": ")),
            expected=_trim(str(answer.get("explanation") or "")),
            impact=impact,
            preconditions=_trim(str(answer.get("trigger_flow") or "")),
            identity_context=_trim(str(answer.get("malicious_actor") or ""), 120),
            cwe=_cwe_for(vtype),
            confidence=conf, p_exploit=conf,
            business_impact=_IMPACT_WEIGHT.get(impact, 0.5)))
    return out


def to_openkritt_output_format(keys=OPENKRITT_FINDING_KEYS) -> list[dict]:
    """Emit an open·kritt step ``output_format`` (``[{"key","type"}, ...]``).

    Lets Aegis hand open·kritt a focused research task whose output maps straight
    back through :func:`ingest_openkritt_findings`. ``line`` is numeric; the rest
    are strings, matching open·kritt's simplified field-type editor.
    """
    return [{"key": k, "type": "number" if k == "line" else "string"} for k in keys]


# --- helpers ---------------------------------------------------------------

def _records(export):
    if export is None:
        return []
    if isinstance(export, str):
        if os.path.exists(export):
            with open(export, encoding="utf-8") as fh:
                export = json.load(fh)
        else:
            export = json.loads(export)
    if isinstance(export, dict):
        for key in ("vulnerabilities", "results", "findings"):
            if isinstance(export.get(key), list):
                return export[key]
        return [export]
    return list(export or [])


def _canonical(rec) -> bool | None:
    for key in ("dedupe_is_canonical", "dedupeIsCanonical"):
        if key in rec and rec[key] is not None:
            return bool(rec[key])
    dedupe = rec.get("dedupe")               # serialized API nests it
    if isinstance(dedupe, dict) and dedupe.get("isCanonical") is not None:
        return bool(dedupe["isCanonical"])
    return None


def _impact_level(rec, answer) -> str:
    """Severity, tolerant of the flat DB shape and the nested serialized shape."""
    bounty = rec.get("bountyRank")
    nested = bounty.get("impactLevel") if isinstance(bounty, dict) else None
    for value in (rec.get("bounty_rank_impact_level"), nested,
                  rec.get("severity"), answer.get("severity")):
        if value:
            return str(value).strip().lower()
    return ""


def _confidence(rec, answer) -> float:
    exploitable = answer.get("exploitable")
    if exploitable is True:
        return 0.6
    if exploitable is False:
        return 0.35
    return 0.45                                     # unknown: modest, still unverified


def _cwe_for(vtype: str) -> str:
    low = (vtype or "").lower()
    for needles, cwe in _CWE_RULES:
        if any(n in low for n in needles):
            return cwe
    return ""


def _asset_for(file_path: str, rec) -> str:
    for key in ("repo", "repository", "scan_repo", "target"):
        if rec.get(key):
            return str(rec[key])
    if file_path:
        return file_path.replace("\\", "/").split("/", 1)[0] or file_path
    return "openkritt"


def _loc(file_path: str, line) -> str:
    if not file_path:
        return ""
    return f"{file_path}:{line}" if line not in (None, "") else file_path


def _trim(text: str, limit: int = 240) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
