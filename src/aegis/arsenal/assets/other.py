"""The "Other" asset lane — classify, then hand back a concrete next command.

Bug bounty programs use "Other" for everything that does not fit their form: a
desktop protocol handler, a Slack app, a browser extension, a support address, a
physical process. There is no honest single scan for that category, so this lane
does the one useful thing it can do deterministically: work out which real lane the
entry actually belongs to and tell the operator exactly how to re-run it.

It performs no network I/O. If it cannot classify the entry, it says so rather than
returning an empty result that reads like a clean scan.
"""

from __future__ import annotations

import re
from typing import Any

from .context import LaneContext
from .results import Observation, TechniqueResult, executed, now
from .types import ArsenalAssetType, classify_identifier

#: Recognizable "Other" shapes and the lane each should be re-run as. Ordered most
#: specific first: ``chrome-extension://`` is also a custom URI scheme, and the
#: extension guidance is the more useful of the two.
_SIGNATURES: tuple[tuple[str, str, str, str], ...] = (
    (r"chrome-extension://|\.crx$|addons\.mozilla\.org", "browser-extension",
     "source_code",
     "unpack the extension (it is a zip of JavaScript) and re-run with "
     "--asset-type source_code --artifact <unpacked path>"),
    (r"\.asar$|electron", "electron-bundle", "executable",
     "re-run with --asset-type executable --artifact <path>; the bundle-unpack "
     "technique routes the JavaScript back into the source lane"),
    (r"npmjs\.com/package/|pypi\.org/project/|rubygems\.org/gems/", "package-registry",
     "source_code",
     "fetch the published artifact and its repository, then re-run with "
     "--asset-type source_code --artifact <path>"),
    (r"hub\.docker\.com|ghcr\.io|\bimage:", "container-image", "executable",
     "export the image filesystem (`docker save`) and re-run with "
     "--asset-type executable --artifact <path>"),
    (r"@|mailto:", "contact-address", "",
     "an email or contact address is a social-engineering surface, which is out of "
     "scope for automated testing and for this arsenal"),
    (r"\bslack\b|\bteams\b|\bdiscord\b.*\bapp\b", "chat-platform-app", "api",
     "the app's backend is the testable surface; obtain its OpenAPI document and "
     "re-run with --asset-type api --api-spec <path>"),
    (r"\bgraphql\b", "graphql-endpoint", "api",
     "introspect the schema yourself and convert it, or supply the REST spec, then "
     "re-run with --asset-type api"),
)


def asset_triage(context: LaneContext) -> TechniqueResult:
    """Classify an unstructured scope entry and name the lane it should be re-run as."""
    technique = "asset-triage"
    started = now()
    identifier = context.asset.strip()
    lowered = identifier.lower()

    matches: list[dict[str, str]] = []
    for pattern, label, lane, guidance in _SIGNATURES:
        if re.search(pattern, lowered):
            matches.append({"shape": label, "suggested_lane": lane, "guidance": guidance})

    inferred: ArsenalAssetType | None = None
    try:
        candidate = classify_identifier(identifier)
        if candidate is not ArsenalAssetType.OTHER_ASSET:
            inferred = candidate
    except ValueError:
        inferred = None

    observations: list[Observation] = []
    if matches:
        primary = matches[0]
        observations.append(Observation(
            technique, f"Scope entry looks like a {primary['shape']}", "info", identifier,
            evidence={"matched_shapes": matches},
            weakness="asset-classification",
            recommendation=primary["guidance"],
        ))
    elif inferred is not None:
        observations.append(Observation(
            technique, f"Scope entry resolves to the {inferred.value} lane", "info",
            identifier, evidence={"inferred_asset_type": inferred.value},
            weakness="asset-classification",
            recommendation=f"re-run with --asset-type {inferred.value}",
        ))

    metadata: dict[str, Any] = {
        "identifier": identifier,
        "matched_shapes": matches,
        "inferred_asset_type": inferred.value if inferred else "",
        "classified": bool(matches or inferred),
    }
    reason = "" if (matches or inferred) else (
        "this entry matched no known asset shape. There is no honest automated technique "
        "for it — review the program's description of the asset and, if it maps to a "
        "supported lane, re-run with an explicit --asset-type"
    )
    return executed(
        technique, context.asset, observations, tool="aegis-asset-triage",
        started_at=started, reason=reason, metadata=metadata,
    )


__all__ = ["asset_triage"]
