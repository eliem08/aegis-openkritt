"""GraphQL authentication-gap analysis (report-corpus driven)."""

from __future__ import annotations

from aegis.active import GraphqlIssue, GraphqlResponse, analyze_graphql


class FakeGraphql:
    """A fake endpoint: `open_resolvers` respond unauth; others return auth errors."""

    def __init__(self, *, introspection=True, open_resolvers=(), db_error_on=()):
        self.introspection = introspection
        self.open = set(open_resolvers)
        self.db_error_on = set(db_error_on)

    def __call__(self, query: str) -> GraphqlResponse:
        if "__schema" in query:
            if self.introspection:
                return GraphqlResponse(200, data_present=True, errors=False)
            return GraphqlResponse(200, data_present=False, errors=True, error_text="unauthorized")
        name = query.split("{", 2)[1].strip().split(" ")[0]
        if name in self.db_error_on:
            return GraphqlResponse(500, data_present=False, errors=True,
                                   error_text='ERROR: relation "error_tags" does not exist (SQLSTATE 42P01)')
        if name in self.open:
            return GraphqlResponse(200, data_present=True, errors=False)
        return GraphqlResponse(200, data_present=False, errors=True, error_text="not authenticated")


def issues(gql, **kw):
    return {f.issue for f in analyze_graphql(gql, **kw)}


# --- introspection -----------------------------------------------------------

def test_unauthenticated_introspection_is_flagged():
    assert GraphqlIssue.INTROSPECTION_ENABLED in issues(FakeGraphql(introspection=True))


def test_protected_introspection_is_clean():
    assert GraphqlIssue.INTROSPECTION_ENABLED not in issues(FakeGraphql(introspection=False))


# --- per-resolver auth gap ---------------------------------------------------

def test_unauthenticated_resolver_is_flagged():
    gql = FakeGraphql(introspection=False, open_resolvers=("error_tags",))
    findings = analyze_graphql(gql, resolvers=["error_tags", "users", "billing"])
    unauth = [f for f in findings if f.issue is GraphqlIssue.UNAUTHENTICATED_RESOLVER]
    assert [f.resolver for f in unauth] == ["error_tags"]      # only the open one


def test_fully_guarded_resolvers_are_clean():
    gql = FakeGraphql(introspection=False, open_resolvers=())
    findings = analyze_graphql(gql, resolvers=["users", "billing"])
    assert all(f.issue is not GraphqlIssue.UNAUTHENTICATED_RESOLVER for f in findings)


# --- raw DB error leak -------------------------------------------------------

def test_raw_database_error_is_flagged():
    gql = FakeGraphql(introspection=False, db_error_on=("error_tags",))
    findings = analyze_graphql(gql, resolvers=["error_tags"])
    assert any(f.issue is GraphqlIssue.RAW_DB_ERROR for f in findings)
