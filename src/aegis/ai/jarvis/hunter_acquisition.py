"""Authorized acquisition of CT, HTML scripts, JavaScript, and declared source maps."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Mapping, Protocol
from urllib.parse import urljoin, urlsplit

from aegis.ai.agentic_os import AuthorizationEnvelope

from .recon_intelligence import CertificateRecord

_SOURCE_MAP = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*(?P<url>[^\s*]+)")


class ArtifactFetcher(Protocol):
    def get(self, url: str) -> tuple[int, Mapping[str, str], bytes]: ...


class CertificateTransparencyProvider(Protocol):
    def query(self, domain: str) -> tuple[CertificateRecord, ...]: ...


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sources: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() != "script":
            return
        source = dict(attrs).get("src")
        if source:
            self.sources.append(source)


@dataclass(frozen=True, slots=True)
class AcquisitionStatus:
    capability: str
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class HunterAcquisitionResult:
    bundles: Mapping[str, str]
    source_maps: Mapping[str, str]
    certificates: tuple[CertificateRecord, ...]
    statuses: tuple[AcquisitionStatus, ...]


class HunterArtifactAcquirer:
    def __init__(self, *, fetcher: ArtifactFetcher | None = None,
                 ct_provider: CertificateTransparencyProvider | None = None,
                 grant_verifier=None, max_artifact_bytes: int = 5_000_000,
                 max_scripts: int = 100) -> None:
        self.fetcher = fetcher
        self.ct_provider = ct_provider
        self.grant_verifier = grant_verifier
        self.max_artifact_bytes = max_artifact_bytes
        self.max_scripts = max_scripts

    def acquire(self, *, page_urls: tuple[str, ...], ct_domains: tuple[str, ...],
                scope_hosts: set[str], authorization: AuthorizationEnvelope) -> HunterAcquisitionResult:
        self._authorize(authorization)
        scope = {item.casefold().rstrip(".") for item in scope_hosts}
        bundles: dict[str, str] = {}
        maps: dict[str, str] = {}
        certificates: list[CertificateRecord] = []
        statuses = []
        if self.fetcher is None:
            statuses.append(AcquisitionStatus("html_script_discovery", "UNAVAILABLE",
                                              "no authorized artifact fetcher is registered"))
        else:
            for page_url in page_urls:
                self._require_scope(page_url, scope)
                status, _headers, body = self.fetcher.get(page_url)
                if status != 200 or len(body) > self.max_artifact_bytes:
                    continue
                parser = _Scripts()
                parser.feed(body.decode("utf-8", "replace"))
                for source in parser.sources[:self.max_scripts]:
                    script_url = urljoin(page_url, source)
                    self._require_scope(script_url, scope)
                    code, _script_headers, script_body = self.fetcher.get(script_url)
                    if code != 200 or len(script_body) > self.max_artifact_bytes:
                        continue
                    text = script_body.decode("utf-8", "replace")
                    bundles[script_url] = text
                    for match in _SOURCE_MAP.finditer(text):
                        map_url = urljoin(script_url, match.group("url").strip())
                        self._require_scope(map_url, scope)
                        map_status, map_headers, map_body = self.fetcher.get(map_url)
                        content_type = next((value for key, value in map_headers.items()
                                             if key.casefold() == "content-type"), "")
                        if (map_status == 200 and len(map_body) <= self.max_artifact_bytes
                                and ("json" in content_type.casefold()
                                     or self._valid_json(map_body))):
                            maps[map_url] = map_body.decode("utf-8", "replace")
            statuses.append(AcquisitionStatus("html_script_discovery", "READY",
                                              f"acquired {len(bundles)} scripts"))
            statuses.append(AcquisitionStatus("authorized_source_map_retrieval", "READY",
                                              f"acquired {len(maps)} declared source maps"))
        if self.ct_provider is None:
            statuses.append(AcquisitionStatus("certificate_transparency", "UNAVAILABLE",
                                              "no CT provider backend is registered"))
        else:
            for domain in ct_domains:
                self._require_domain_scope(domain, scope)
                certificates.extend(self.ct_provider.query(domain))
            statuses.append(AcquisitionStatus("certificate_transparency", "READY",
                                              f"acquired {len(certificates)} records"))
        return HunterAcquisitionResult(bundles, maps, tuple(certificates), tuple(statuses))

    def _authorize(self, authorization: AuthorizationEnvelope) -> None:
        grant = authorization.grant
        if (grant is None or grant.scope_digest != authorization.scope_digest
                or not grant.verify(self.grant_verifier) or not grant.network_allowed):
            raise PermissionError("acquisition requires a verified scope-bound network grant")

    @staticmethod
    def _allowed(host: str, scope: set[str]) -> bool:
        return host in scope or any(
            item.startswith("*.")
            and (host == item[2:] or host.endswith(item[1:]))
            for item in scope
        )

    @classmethod
    def _require_scope(cls, url: str, scope: set[str]) -> None:
        host = (urlsplit(url).hostname or "").casefold().rstrip(".")
        if not host or not cls._allowed(host, scope):
            raise PermissionError(f"artifact URL is outside confirmed scope: {host or url}")

    @classmethod
    def _require_domain_scope(cls, domain: str, scope: set[str]) -> None:
        host = domain.casefold().strip().lstrip("*.").rstrip(".")
        if not host or not cls._allowed(host, scope):
            raise PermissionError(f"CT query domain is outside confirmed scope: {domain}")

    @staticmethod
    def _valid_json(body: bytes) -> bool:
        try:
            value = json.loads(body)
            return isinstance(value, dict) and value.get("version") == 3
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False


__all__ = [
    "AcquisitionStatus", "ArtifactFetcher", "CertificateTransparencyProvider",
    "HunterAcquisitionResult", "HunterArtifactAcquirer",
]
