"""Turn a confirmed hypothesis into a reproduction scaffold a human can run.

Every serious program (Vercel, Matomo, owncloud) rejects code-analysis findings
without a working proof-of-concept validated on a running instance. Aegis can locate
and reason about a candidate but it must not submit — a human runs the scaffold,
confirms real impact, and files the report. This module writes that scaffold:

* ``report.md``  — the finding in the structure these programs ask for (affected
  version, entry point, trust model, impact, reproduction steps, remediation).
* ``repro.py``   — an editable HTTP reproduction skeleton (never fires by default;
  the human sets ``TARGET`` and removes the safety guard).
* ``run.md``     — how to stand up a local instance to test against, when the target
  ships a docker-compose.

Nothing here executes an exploit or contacts a target; it produces artifacts only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PoCArtifacts:
    directory: Path
    report_path: Path
    repro_path: Path
    runbook_path: Path


def _get(answer: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = answer.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def build_poc(row: dict, *, repository: str, out_dir: str | Path,
              program_handle: str = "", commit: str = "",
              compose_hint: str | None = None) -> PoCArtifacts:
    """Write a reproduction scaffold for one validated finding row.

    ``row`` is a persisted-report vulnerability entry (the ``json_answer`` +
    ``validation`` shape). Only rows a human should chase should be passed here —
    typically the confirmed ones — but the caller decides.
    """
    answer = row.get("json_answer") or {}
    validation = row.get("validation") or {}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    weakness = _get(answer, "vulnerability_type", "weakness", default="Security issue")
    title = _get(answer, "summary", "title", default=weakness)
    file_path = _get(answer, "file_path")
    line = answer.get("line", "")
    severity = _get(answer, "severity", default=row.get("severity", "medium"))
    entry_point = _get(answer, "trigger_flow", "entry_point")
    attacker = _get(answer, "malicious_actor", "attacker")
    impact = _get(answer, "impact")
    rationale = _get(answer, "explanation", "rationale")
    trust_model = _get(validation, "trust_model")
    verdict = _get(validation, "verdict", default="unresolved")

    report = _report_md(
        repository=repository, program_handle=program_handle, commit=commit,
        weakness=weakness, title=title, file_path=file_path, line=line,
        severity=severity, entry_point=entry_point, attacker=attacker, impact=impact,
        rationale=rationale, trust_model=trust_model, verdict=verdict,
    )
    report_path = out / "report.md"
    report_path.write_text(report, encoding="utf-8")

    repro_path = out / "repro.py"
    repro_path.write_text(_repro_py(title=title, entry_point=entry_point,
                                    file_path=file_path), encoding="utf-8")

    runbook_path = out / "run.md"
    runbook_path.write_text(_runbook_md(repository=repository, compose_hint=compose_hint),
                            encoding="utf-8")
    return PoCArtifacts(out, report_path, repro_path, runbook_path)


def annotate_reproduction(report_path: str | Path, *, triggered: bool, summary: str,
                          evidence: str = "") -> None:
    """Append the reproduction-agent outcome to a scaffolded report.md, so a locally
    reproduced finding is visibly distinguished from an unverified draft."""
    path = Path(report_path)
    status = "✅ REPRODUCED locally" if triggered else "❌ NOT reproduced locally"
    block = (
        "\n\n## Local reproduction (Aegis reproduction agent)\n"
        f"- **Outcome:** {status}\n"
        f"- **Summary:** {summary}\n"
    )
    if evidence:
        block += f"\n```\n{evidence[:4000]}\n```\n"
    if not triggered:
        block += ("\n> Still human-unverified. A machine reproduction that did not trigger "
                  "is not proof the bug is absent — reproduce by hand before deciding.\n")
    path.write_text(path.read_text(encoding="utf-8") + block, encoding="utf-8")


def _report_md(**f) -> str:
    unresolved_banner = (
        "" if f["verdict"] == "confirmed" else
        f"> ⚠️ Aegis verdict is **{f['verdict']}**, not confirmed. Do not submit until "
        "you have reproduced real impact on a running instance.\n\n"
    )
    return (
        f"# {f['title']}\n\n"
        f"{unresolved_banner}"
        "> DRAFT — machine-located, human-unverified. This program rejects unverified "
        "AI/scanner output. Reproduce on a running instance and confirm real impact "
        "before submitting.\n\n"
        f"- **Project / asset:** {f['repository']}"
        + (f" (HackerOne: `{f['program_handle']}`)" if f["program_handle"] else "") + "\n"
        f"- **Affected version / commit:** {f['commit'] or 'FILL IN — the release you reproduced on'}\n"
        f"- **Weakness:** {f['weakness']}\n"
        f"- **Severity (self-assessed):** {f['severity']}\n"
        f"- **Location:** `{f['file_path']}`" + (f":{f['line']}" if f["line"] else "") + "\n\n"
        "## Required authentication level\n"
        f"{f['attacker'] or 'FILL IN — unauthenticated / user / admin / superuser'}\n\n"
        "## Trust model (what the attacker must already possess)\n"
        f"{f['trust_model'] or 'FILL IN — confirm the attacker needs nothing they cannot obtain'}\n\n"
        "## Entry point\n"
        f"{f['entry_point'] or 'FILL IN — the request/route/parameter that reaches the code'}\n\n"
        "## Root cause\n"
        f"{f['rationale']}\n\n"
        "## Impact\n"
        f"{f['impact'] or 'FILL IN — what an attacker concretely reads, writes, or executes'}\n\n"
        "## Reproduction steps\n"
        "1. Stand up a local instance (see `run.md`).\n"
        "2. Edit and run `repro.py` against it.\n"
        "3. FILL IN the exact observed result that proves impact (response, DB state, "
        "file written, code executed).\n\n"
        "## Proof of concept\n"
        "Attach the request/response, a screenshot or short video, and the `repro.py` "
        "you ran. Reports without a working PoC are marked Not Applicable.\n\n"
        "## Suggested remediation\n"
        "FILL IN — the guard/check that closes the traced path (optional; may earn a bonus).\n"
    )


def _repro_py(*, title: str, entry_point: str, file_path: str) -> str:
    return (
        '"""Reproduction skeleton — EDIT before use. Does not fire until you set\n'
        'TARGET to your own local instance and remove the safety guard below.\n\n'
        f"Finding: {title}\n"
        f"Location: {file_path}\n"
        f"Entry point: {entry_point or 'FILL IN'}\n"
        '"""\n\n'
        "import sys\n"
        "import httpx\n\n"
        '# Point this ONLY at a local instance you control (see run.md).\n'
        'TARGET = "http://127.0.0.1:8080"\n\n'
        'if "REMOVE_THIS_GUARD" in TARGET or TARGET.startswith("http://127.0.0.1:8080"):\n'
        '    sys.exit("Edit repro.py: set TARGET to your own local instance first.")\n\n'
        "def main() -> None:\n"
        "    client = httpx.Client(base_url=TARGET, timeout=15)\n"
        "    # FILL IN: build the request that reaches the traced entry point.\n"
        "    # resp = client.get(\"/...\")\n"
        "    # print(resp.status_code, resp.text[:500])\n"
        "    # Assert the concrete impact (cross-user read, auth bypass, etc.).\n"
        "    raise SystemExit(\"Fill in the request and the impact assertion.\")\n\n"
        'if __name__ == "__main__":\n'
        "    main()\n"
    )


def _runbook_md(*, repository: str, compose_hint: str | None) -> str:
    if compose_hint:
        return (
            f"# Local instance for {repository}\n\n"
            "This project ships a compose file, so you can validate locally:\n\n"
            "```bash\n"
            f"git clone https://github.com/{repository}.git\n"
            f"cd {repository.split('/')[-1]}\n"
            f"{compose_hint}\n"
            "```\n\n"
            "Then set `TARGET` in `repro.py` to the local URL and run it. Only ever test "
            "against this local instance — never the program's production systems.\n"
        )
    return (
        f"# Local instance for {repository}\n\n"
        "No compose file was detected automatically. Stand up a supported release "
        "locally using the project's documented setup, then point `repro.py` at it.\n\n"
        "Rules of engagement for every program in scope: test only against your own "
        "local instance, never production, and never access data that is not yours.\n"
    )


def detect_compose_hint(repo_root: str | Path) -> str | None:
    """A best-effort local-run command if the checkout has an obvious entry point."""
    root = Path(repo_root)
    if (root / "docker-compose.yml").is_file() or (root / "docker-compose.yaml").is_file():
        return "docker compose up -d"
    if (root / "Dockerfile").is_file():
        name = Path(repo_root).name.lower()
        return f"docker build -t {name} . && docker run -p 8080:80 {name}"
    return None


def build_pocs_from_report(report_path: str | Path, out_root: str | Path, *,
                           program_handle: str = "", only_confirmed: bool = True,
                           repo_root: str | Path | None = None) -> list[PoCArtifacts]:
    """Scaffold a PoC per finding in a persisted report (confirmed ones by default)."""
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    scan = data.get("scan") or {}
    repository = scan.get("repository", "")
    commit = scan.get("commit", "")
    compose_hint = detect_compose_hint(repo_root) if repo_root else None
    out_root = Path(out_root)
    artifacts: list[PoCArtifacts] = []
    for index, row in enumerate(data.get("vulnerabilities") or []):
        verdict = (row.get("validation") or {}).get("verdict")
        if only_confirmed and verdict != "confirmed":
            continue
        answer = row.get("json_answer") or {}
        slug = f"{index:02d}-" + (answer.get("vulnerability_type") or "finding").split(":")[0]
        slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in slug)[:60]
        artifacts.append(build_poc(
            row, repository=repository, out_dir=out_root / slug,
            program_handle=program_handle, commit=commit, compose_hint=compose_hint,
        ))
    return artifacts
