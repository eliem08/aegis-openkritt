"""Concrete GraphQL authorization differential over the scoped HTTP lane."""

from __future__ import annotations

import json
from collections.abc import Mapping

from .execution_errors import MissionPrerequisiteError
from .http_identity_executor import HttpIdentityDifferentialExecutor
from .identity_fixtures import FixtureProtocol
from .identity_intelligence import SyntheticResource


class GraphQLAuthorizationDifferentialExecutor(HttpIdentityDifferentialExecutor):
    CAPABILITY = "dynamic:graphql-auth-differential"

    def __init__(self, http, *, fixture_sets, credential_resolver, grant_verifier) -> None:
        super().__init__(
            http,
            fixture_sets=fixture_sets,
            credential_resolver=credential_resolver,
            grant_verifier=grant_verifier,
            protocol=FixtureProtocol.GRAPHQL,
            capabilities=(self.CAPABILITY,),
        )

    @staticmethod
    def _request_spec(
        payload: Mapping[str, object], endpoint: str, resource: SyntheticResource
    ) -> tuple[str, str, dict[str, str], bytes]:
        query = str(payload.get("query") or "")
        if not query.strip() or not str(payload.get("field_path") or "").strip():
            raise MissionPrerequisiteError(
                "GraphQL differential requires a controlled query and expected field path"
            )
        raw_variables = payload.get("variables") or {}
        if not isinstance(raw_variables, Mapping):
            raise MissionPrerequisiteError("GraphQL variables must be a mapping")

        def substitute(value):
            if isinstance(value, str):
                return value.replace("{resource_id}", resource.resource_id).replace(
                    "{canary}", resource.canary
                )
            if isinstance(value, Mapping):
                return {str(key): substitute(item) for key, item in value.items()}
            if isinstance(value, list):
                return [substitute(item) for item in value]
            return value

        document = {
            "query": query,
            "variables": substitute(raw_variables),
            "operationName": payload.get("operation_name") or None,
        }
        return (
            "POST",
            endpoint.replace("{resource_id}", resource.resource_id),
            {"content-type": "application/json", "accept": "application/json"},
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )


__all__ = ["GraphQLAuthorizationDifferentialExecutor"]
