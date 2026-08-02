"""GraphQL authentication-gap analysis (report-corpus driven).

GraphQL failures in the corpus are per-resolver, not systemic: auth middleware
exists globally but is omitted from a few resolvers (the observability endpoint's
three unguarded resolvers; Hasura anonymous PII). The tells are: introspection
answered to an anonymous caller, a specific query returning data unauthenticated
while others return auth errors, and raw database errors (SQLSTATE, relation
names) leaking to clients.

Transport-agnostic: the caller supplies ``probe(query) -> GraphqlResponse`` that
POSTs an *unauthenticated* query through the gateway. Read-only queries only —
mutations (state-changing) are never sent here. Findings are candidates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable

INTROSPECTION_QUERY = "{ __schema { queryType { name } } }"

_DB_ERROR = re.compile(
    r"(SQLSTATE|pg_[a-z]+|postgres|duplicate key|violates unique constraint|"
    r'relation "[^"]+" does not exist|syntax error at|ORA-\d{3,}|"[a-z_]+_pkey")', re.I)


@dataclass(frozen=True)
class GraphqlResponse:
    status: int
    data_present: bool          # a non-null `data` field with content came back
    errors: bool                # an `errors` array was present
    error_text: str = ""


class GraphqlIssue(str, Enum):
    INTROSPECTION_ENABLED = "introspection_enabled"
    UNAUTHENTICATED_RESOLVER = "unauthenticated_resolver"
    RAW_DB_ERROR = "raw_db_error"


@dataclass(frozen=True)
class GraphqlFinding:
    issue: GraphqlIssue
    detail: str
    resolver: str = ""
    confidence: float = 0.7
    verified: bool = False


def analyze_graphql(probe: Callable[[str], GraphqlResponse], *, resolvers=()) -> list[GraphqlFinding]:
    findings: list[GraphqlFinding] = []

    intro = probe(INTROSPECTION_QUERY)
    _check_db_error(intro, findings)
    if intro.data_present and not intro.errors:
        findings.append(GraphqlFinding(
            GraphqlIssue.INTROSPECTION_ENABLED,
            "schema introspection answered to an unauthenticated caller", confidence=0.6))

    for resolver in resolvers:
        resp = probe("{ %s { __typename } }" % resolver)
        _check_db_error(resp, findings, resolver)
        if resp.data_present and not resp.errors:
            findings.append(GraphqlFinding(
                GraphqlIssue.UNAUTHENTICATED_RESOLVER,
                f"resolver {resolver!r} returned data with no authentication",
                resolver=resolver, confidence=0.85))
    return findings


def _check_db_error(resp: GraphqlResponse, findings: list, resolver: str = "") -> None:
    if resp.error_text and _DB_ERROR.search(resp.error_text):
        findings.append(GraphqlFinding(
            GraphqlIssue.RAW_DB_ERROR,
            "raw database error leaked to the client", resolver=resolver, confidence=0.7))
