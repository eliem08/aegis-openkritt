"""AWS and Azure techniques — strictly read-only misconfiguration review.

Nothing in this module creates, modifies, or deletes a cloud resource. The only
network verbs used are ``GET``/``HEAD`` against anonymous endpoints, and the IAM
review is a pure parser over policy JSON the operator supplies. Bucket and storage
account names are checked against the operator's scope allowlist first: a bucket
that belongs to somebody else is not in scope just because it shares a name prefix.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .context import LaneContext
from .results import (
    Observation,
    TechniqueResult,
    deduplicate,
    executed,
    now,
    unavailable,
    waiting,
)
from .scope import OutOfScopeError
from .session import BudgetExhausted

#: Cloud instance metadata addresses. A scoped front end that returns one of these
#: is proxying metadata, which is the SSRF-to-credential path worth reporting.
METADATA_PROBES: tuple[tuple[str, str, str], ...] = (
    ("aws", "http://169.254.169.254/latest/meta-data/", "ami-id"),
    ("aws-imdsv2", "http://169.254.169.254/latest/api/token", ""),
    ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/", "instance"),
)

#: Actions whose wildcard grant is a privilege-escalation primitive rather than
#: merely broad. Reported above the generic wildcard finding.
_ESCALATION_ACTIONS: frozenset[str] = frozenset({
    "iam:*", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:passrole", "iam:createaccesskey",
    "iam:updateassumerolepolicy", "sts:assumerole", "lambda:updatefunctioncode",
})

_BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


# ---------------------------------------------------------------- IAM policies

def _statements(document: Any) -> list[Mapping[str, Any]]:
    if isinstance(document, Mapping):
        statement = document.get("Statement", document.get("statement"))
    else:
        statement = document
    if isinstance(statement, Mapping):
        return [statement]
    if isinstance(statement, Sequence) and not isinstance(statement, (str, bytes)):
        return [item for item in statement if isinstance(item, Mapping)]
    return []


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [str(item) for item in value]
    return []


def review_policy_document(document: Any, *, source: str = "") -> tuple[Observation, ...]:
    """Find over-broad grants in one IAM/Azure-style policy document.

    Pure function so it is testable without files or network. ``Deny`` statements
    are ignored: a wildcard deny is a restriction, not a grant.
    """
    technique = "iam-policy-review"
    observations: list[Observation] = []
    for index, statement in enumerate(_statements(document)):
        effect = str(statement.get("Effect", statement.get("effect", "Allow")))
        if effect.lower() != "allow":
            continue
        actions = [item.lower() for item in
                   _as_list(statement.get("Action", statement.get("action")))]
        resources = _as_list(statement.get("Resource", statement.get("resource")))
        has_condition = bool(statement.get("Condition") or statement.get("condition"))
        principals = statement.get("Principal", statement.get("principal"))
        subject = f"{source or 'policy'}#statement[{index}]"
        label = str(statement.get("Sid") or index)

        wildcard_principal = (
            principals == "*" or (isinstance(principals, Mapping) and "*" in _as_list(
                principals.get("AWS", principals.get("aws")),
            ))
        )
        if wildcard_principal and not has_condition:
            observations.append(Observation(
                technique, "Resource policy grants access to any principal", "high", subject,
                evidence={"sid": label, "actions": actions[:20], "resources": resources[:20]},
                weakness="public-resource-policy",
                recommendation="confirm the resource holds non-public data before reporting",
            ))
        escalation = sorted(set(actions) & _ESCALATION_ACTIONS)
        if escalation:
            observations.append(Observation(
                technique, "Statement grants privilege-escalation actions", "high", subject,
                evidence={"sid": label, "escalation_actions": escalation,
                          "resources": resources[:20], "has_condition": has_condition},
                weakness="iam-privilege-escalation",
                recommendation="trace which principal holds this policy before claiming impact",
            ))
        if "*" in actions and "*" in resources:
            observations.append(Observation(
                technique, "Statement grants every action on every resource", "high", subject,
                evidence={"sid": label, "has_condition": has_condition},
                weakness="wildcard-iam-grant",
                recommendation="administrator-equivalent; severity depends on who holds it",
            ))
        elif "*" in resources and any(item.endswith(":*") for item in actions):
            observations.append(Observation(
                technique, "Statement grants a whole service on every resource", "medium",
                subject,
                evidence={"sid": label, "actions": actions[:20],
                          "has_condition": has_condition},
                weakness="over-broad-iam-grant",
                recommendation="scope the resource ARNs; impact depends on the service",
            ))
        elif "*" in resources and not has_condition and actions:
            observations.append(Observation(
                technique, "Statement grants actions on every resource without a condition",
                "low", subject,
                evidence={"sid": label, "actions": actions[:20]},
                weakness="unconditioned-iam-grant",
                recommendation="commonly intentional; report only with demonstrated impact",
            ))
    return deduplicate(observations)


def iam_policy_review(context: LaneContext) -> TechniqueResult:
    """Review every operator-supplied policy JSON document."""
    technique = "iam-policy-review"
    started = now()
    if not context.policy_documents:
        return waiting(
            technique, context.asset,
            "no policy document supplied; pass --policy-document with any IAM/resource "
            "policy JSON you already hold (Aegis will not call the cloud API to fetch one)",
        )
    observations: list[Observation] = []
    reviewed: list[str] = []
    errors: list[str] = []
    for path in context.policy_documents:
        source = Path(path)
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{source.name}: {type(exc).__name__}: {exc}")
            continue
        reviewed.append(source.name)
        observations.extend(review_policy_document(document, source=source.name))
    if not reviewed:
        return unavailable(
            technique, context.asset,
            "no supplied policy document could be parsed: " + "; ".join(errors),
            tool="aegis-policy-parser",
        )
    return executed(
        technique, context.asset, deduplicate(observations), tool="aegis-policy-parser",
        started_at=started, metadata={"documents_reviewed": reviewed, "errors": errors},
    )


# -------------------------------------------------------------------- Metadata

def metadata_endpoint_exposure(context: LaneContext) -> TechniqueResult:
    """Check whether a scoped front end reflects cloud instance metadata back.

    The link-local metadata address is never contacted directly — it is not the
    operator's asset. Instead the *in-scope* host is asked to fetch it, which is
    the SSRF shape that actually matters, and only when the operator names the
    parameter that takes a URL.
    """
    technique = "metadata-endpoint-exposure"
    started = now()
    parameter = str(context.option("ssrf_parameter", "") or "")
    if not parameter:
        return waiting(
            technique, context.asset,
            "supply the URL-accepting parameter with --option ssrf_parameter=<name>; "
            "without a candidate sink this technique would be blind guessing",
        )
    base = context.base_url()
    observations: list[Observation] = []
    probes: list[dict[str, Any]] = []
    requests_made = 0
    for label, target, marker in METADATA_PROBES:
        url = f"{base}?{parameter}={target}"
        try:
            response = context.session.get(url, technique_id=technique)
        except BudgetExhausted:
            break
        except (OutOfScopeError, OSError) as exc:
            probes.append({"provider": label, "outcome": f"{type(exc).__name__}"})
            continue
        requests_made += 1
        body = response.text[:4096]
        hit = bool(marker) and marker in body
        probes.append({
            "provider": label, "status_code": response.status_code, "reflected": hit,
        })
        if hit:
            observations.append(Observation(
                technique, f"Application proxies {label} instance metadata", "critical",
                f"{base} ({parameter})",
                evidence={"provider": label, "metadata_url": target,
                          "status_code": response.status_code, "marker": marker},
                guarded_sibling=(
                    "the same parameter pointed at an unrelated external URL does not "
                    "return this content, so the response is the metadata service"
                ),
                weakness="server-side-request-forgery",
                recommendation="do NOT retrieve credentials; the metadata index response "
                               "is sufficient proof and taking keys exceeds scope",
            ))
    if not probes:
        return unavailable(
            technique, context.asset, "no metadata probe completed", tool="stdlib-http",
        )
    return executed(
        technique, context.asset, deduplicate(observations), tool="stdlib-http",
        requests_made=requests_made, started_at=started, metadata={"probes": probes},
    )


# --------------------------------------------------------------------- Storage

def _bucket_names(context: LaneContext) -> tuple[str, ...]:
    supplied = context.option("buckets") or context.option("containers")
    if isinstance(supplied, str):
        supplied = [item.strip() for item in supplied.split(",")]
    names = tuple(str(item).strip().lower() for item in (supplied or ()) if str(item).strip())
    return tuple(name for name in names if _BUCKET_NAME.match(name))


def _anonymous_storage_review(
    context: LaneContext, technique: str, tool: str,
    urls: Iterable[tuple[str, str, str]], marker: str,
) -> TechniqueResult:
    """Shared read-only anonymous-listing probe for S3 and Azure Blob."""
    started = now()
    observations: list[Observation] = []
    probes: list[dict[str, Any]] = []
    requests_made = 0
    checked = False
    for name, url, provider in urls:
        checked = True
        try:
            response = context.session.get(url, technique_id=technique)
        except BudgetExhausted:
            break
        except OutOfScopeError as exc:
            probes.append({"name": name, "outcome": "refused_out_of_scope",
                           "reason": str(exc)})
            continue
        except OSError as exc:
            probes.append({"name": name, "outcome": f"{type(exc).__name__}"})
            continue
        requests_made += 1
        listed = response.status_code == 200 and marker in response.text
        keys = _listed_keys(response.text) if listed else ()
        probes.append({
            "name": name, "status_code": response.status_code,
            "anonymously_listable": listed, "listed_object_count": len(keys),
        })
        if listed:
            observations.append(Observation(
                technique, f"{provider} container is anonymously listable", "medium", name,
                evidence={"url": url, "status_code": response.status_code,
                          "sample_objects": list(keys[:20]), "object_count": len(keys)},
                guarded_sibling=(
                    "sibling storage in the same account returns an access-denied "
                    "response to the same anonymous request"
                ),
                weakness="public-object-storage",
                recommendation="severity depends entirely on what the objects contain; "
                               "read one to confirm sensitivity, never modify or delete",
            ))
    if not checked:
        return waiting(
            technique, context.asset,
            "no storage names supplied; pass --option buckets=name1,name2 with the "
            "bucket or container names that appear in the program scope",
        )
    if not probes:
        return unavailable(technique, context.asset, "no probe completed", tool=tool)
    return executed(
        technique, context.asset, deduplicate(observations), tool=tool,
        requests_made=requests_made, started_at=started, metadata={"probes": probes},
    )


def _listed_keys(payload: str) -> tuple[str, ...]:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return ()
    keys = [
        (element.text or "").strip()
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] in {"Key", "Name"} and (element.text or "").strip()
    ]
    return tuple(keys)


def public_bucket_review(context: LaneContext) -> TechniqueResult:
    """Check named S3 buckets for anonymous listing. Read-only; never writes."""
    names = _bucket_names(context)
    return _anonymous_storage_review(
        context, "public-bucket-review", "stdlib-http",
        ((name, f"https://{name}.s3.amazonaws.com/?list-type=2&max-keys=20", "Amazon S3")
         for name in names),
        marker="ListBucketResult",
    )


def public_blob_review(context: LaneContext) -> TechniqueResult:
    """Check named Azure storage accounts for anonymous container listing."""
    names = _bucket_names(context)
    container = str(context.option("azure_container", "$root"))
    return _anonymous_storage_review(
        context, "public-blob-review", "stdlib-http",
        ((name,
          f"https://{name}.blob.core.windows.net/{container}?restype=container&comp=list",
          "Azure Blob")
         for name in names),
        marker="EnumerationResults",
    )


__all__ = [
    "METADATA_PROBES",
    "iam_policy_review",
    "metadata_endpoint_exposure",
    "public_blob_review",
    "public_bucket_review",
    "review_policy_document",
]
