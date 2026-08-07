"""Nuclei adapter (Phase 3 §Nuclei adapter).

Nuclei runs community-authored templates, so the whole safety story is: *which
templates are allowed to run, and can we prove they are what we approved?* That
lives in an **Aegis-maintained, signed template manifest** — not in Nuclei's own
template directory, which is untrusted input.

The manifest pins the executable and template-repo commit, and lists every
approved template by id with its content checksum, signer, severity, tags,
protocol, request budget, and capability tier. The adapter:

* verifies the manifest's signature and refuses templates whose signer is not
  trusted (unsigned), whose checksum does not match (tampered), that are not in
  the manifest (unknown / newly added), or that are referenced by a local path;
* disables code, JavaScript, file, network, headless, fuzzing, and OAST
  protocols by default — enabling any needs a manifest entry *and* matching
  authorization;
* disables automatic template updates for the run;
* parses results into ``FINDING`` candidates preserving template/version
  provenance — a candidate, never a verified finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from .base import JsonLinesAdapter, SchemaMismatch
from .contract import AdapterManifest, CapabilityTier, EventKind, ExecutionEnvelope

# Nuclei protocol types that are safe to run without extra authorization.
DEFAULT_ALLOWED_PROTOCOLS = ("http", "ssl", "dns")
# Everything here is off unless a manifest entry *and* the authorization enable it.
PROHIBITED_PROTOCOLS = (
    "code", "javascript", "js", "file", "network", "tcp", "headless",
    "whois", "websocket", "oast",
)


class ManifestError(RuntimeError):
    """The template manifest is unsigned, tampered, or internally inconsistent."""


class RejectReason:
    UNKNOWN = "unknown_template"
    TAMPERED = "tampered_template"
    UNSIGNED = "unsigned_template"
    PROHIBITED = "prohibited_protocol"
    LOCAL_REF = "locally_referenced_template"
    MISSING = "missing_template_file"


@dataclass(frozen=True)
class TemplateEntry:
    template_id: str
    checksum: str            # sha256 of the template file content
    signer: str
    severity: str
    protocol: str
    tags: tuple[str, ...] = ()
    max_requests: int = 50
    capability_tier: str = CapabilityTier.TEMPLATE_SCAN.value


@dataclass(frozen=True)
class TemplateVerdict:
    ok: bool
    reason: str = ""


@dataclass
class TemplateManifest:
    manifest_id: str
    version: int
    executable_digest: str
    template_commit: str          # pinned template-repo commit
    entries: dict                 # template_id -> TemplateEntry
    trusted_signers: frozenset
    allowed_protocols: frozenset = frozenset(DEFAULT_ALLOWED_PROTOCOLS)
    created_at: str = ""
    signing_key_id: str | None = None
    signature: str | None = None

    # -- signing ------------------------------------------------------------

    def signing_payload(self) -> dict:
        return {
            "manifest_id": self.manifest_id,
            "version": self.version,
            "executable_digest": self.executable_digest,
            "template_commit": self.template_commit,
            "allowed_protocols": sorted(self.allowed_protocols),
            "entries": {
                tid: [e.template_id, e.checksum, e.signer, e.severity, e.protocol,
                      sorted(e.tags), e.max_requests, e.capability_tier]
                for tid, e in sorted(self.entries.items())
            },
        }

    def verify(self, verifier) -> None:
        """Fail closed unless the manifest is signed by a trusted key and every
        entry's signer is trusted."""
        if not self.signature or not self.signing_key_id:
            raise ManifestError("template manifest is unsigned")
        if not verifier.verify(self.signing_payload(), self.signature, self.signing_key_id):
            raise ManifestError("template manifest signature is invalid")
        for entry in self.entries.values():
            if entry.signer not in self.trusted_signers:
                raise ManifestError(f"template {entry.template_id!r} has untrusted signer {entry.signer!r}")
        for proto in self.allowed_protocols:
            if proto in PROHIBITED_PROTOCOLS:
                raise ManifestError(f"manifest allows prohibited protocol {proto!r} without review")

    # -- validation ---------------------------------------------------------

    def validate(self, template_id: str, *, checksum: str | None = None,
                 protocol: str | None = None) -> TemplateVerdict:
        if _looks_local(template_id):
            return TemplateVerdict(False, RejectReason.LOCAL_REF)
        entry = self.entries.get(template_id)
        if entry is None:
            return TemplateVerdict(False, RejectReason.UNKNOWN)      # unknown / newly added
        if entry.signer not in self.trusted_signers:
            return TemplateVerdict(False, RejectReason.UNSIGNED)
        if protocol is not None and not self._protocol_ok(protocol):
            return TemplateVerdict(False, RejectReason.PROHIBITED)
        if checksum is not None and checksum != entry.checksum:
            return TemplateVerdict(False, RejectReason.TAMPERED)
        return TemplateVerdict(True)

    def _protocol_ok(self, protocol: str) -> bool:
        p = (protocol or "").lower()
        return p in self.allowed_protocols and p not in PROHIBITED_PROTOCOLS

    def verify_template_files(self, loader: Callable[[str], bytes]) -> dict:
        """Pre-scan integrity: checksum every approved template's actual content.

        Returns ``{template_id: TemplateVerdict}``; a mismatch is *tampered*, a
        missing file is *missing*. Only ``ok`` templates should be run.
        """
        verdicts = {}
        for tid, entry in self.entries.items():
            try:
                content = loader(tid)
            except (FileNotFoundError, KeyError):
                verdicts[tid] = TemplateVerdict(False, RejectReason.MISSING)
                continue
            digest = hashlib.sha256(content).hexdigest()
            verdicts[tid] = (TemplateVerdict(True) if digest == entry.checksum
                             else TemplateVerdict(False, RejectReason.TAMPERED))
        return verdicts

    @property
    def approved_ids(self) -> list[str]:
        return sorted(self.entries)

    @classmethod
    def from_dict(cls, data: dict) -> TemplateManifest:
        entries = {
            tid: TemplateEntry(
                template_id=e["template_id"], checksum=e["checksum"], signer=e["signer"],
                severity=e.get("severity", "info"), protocol=e.get("protocol", "http"),
                tags=tuple(e.get("tags", ())), max_requests=int(e.get("max_requests", 50)),
                capability_tier=e.get("capability_tier", CapabilityTier.TEMPLATE_SCAN.value),
            )
            for tid, e in data["entries"].items()
        }
        return cls(
            manifest_id=data["manifest_id"], version=int(data["version"]),
            executable_digest=data.get("executable_digest", ""),
            template_commit=data.get("template_commit", ""), entries=entries,
            trusted_signers=frozenset(data.get("trusted_signers", ())),
            allowed_protocols=frozenset(data.get("allowed_protocols", DEFAULT_ALLOWED_PROTOCOLS)),
            created_at=data.get("created_at", ""),
            signing_key_id=data.get("signing_key_id"), signature=data.get("signature"),
        )


def sign_manifest(manifest: TemplateManifest, verifier, key_id: str) -> TemplateManifest:
    """Attach a signature (used by the manifest tooling and tests)."""
    manifest.signing_key_id = key_id
    manifest.signature = verifier.sign(manifest.signing_payload(), key_id)
    return manifest


# --- adapter ---------------------------------------------------------------

@dataclass(frozen=True)
class NucleiConfig:
    rate_limit: int = 150
    concurrency: int = 25
    timeout_seconds: int = 10
    max_host_errors: int = 30
    max_requests: int | None = None
    authorized_protocols: tuple[str, ...] = DEFAULT_ALLOWED_PROTOCOLS


class NucleiAdapter(JsonLinesAdapter):
    tool_name = "nuclei"

    def __init__(self, manifest: TemplateManifest, executable=None, *,
                 config: NucleiConfig | None = None, verifier=None, **kw) -> None:
        super().__init__(executable, **kw)
        if verifier is not None:
            manifest.verify(verifier)             # fail closed before anything runs
        self.template_manifest = manifest
        self.config = config or NucleiConfig()
        self.manifest = AdapterManifest(
            name="nuclei", version="3.3.0", executable_digest=manifest.executable_digest,
            license="MIT", capability_tier=CapabilityTier.TEMPLATE_SCAN.value,
            input_schema_version=1, output_schema_version=3, network_profile="target-mutation",
        )
        self._findings = 0
        self._rejected: dict[str, int] = {}

    # Effective protocols: manifest-allowed ∩ authorized, minus prohibited.
    def _effective_protocols(self) -> list[str]:
        authorized = {p.lower() for p in self.config.authorized_protocols}
        return sorted(p for p in self.template_manifest.allowed_protocols
                      if p in authorized and p not in PROHIBITED_PROTOCOLS)

    def build_command(self, envelope: ExecutionEnvelope) -> list[str]:
        cfg = self.config
        argv = [
            self.resolve_executable(),
            "-target", envelope.target,
            "-jsonl", "-silent", "-no-color",
            "-disable-update-check",              # no template auto-update mid-scan
            "-no-interactsh",                     # OAST off by default
            "-headless=false",
            "-dast=false",                        # no fuzzing
            "-type", ",".join(self._effective_protocols()),
            "-exclude-type", ",".join(PROHIBITED_PROTOCOLS),
            "-rate-limit", str(cfg.rate_limit),
            "-concurrency", str(cfg.concurrency),
            "-timeout", str(cfg.timeout_seconds),
            "-max-host-error", str(cfg.max_host_errors),
            # Only approved template ids run; nothing from the raw template dir.
            "-template-id", ",".join(self.template_manifest.approved_ids),
        ]
        if cfg.max_requests is not None:
            argv += ["-rate-limit-duration", "1", "-max-requests", str(cfg.max_requests)]
        return argv

    def preflight(self, loader: Callable[[str], bytes]) -> dict:
        """Verify approved templates on disk before the run; caller drops any
        that are tampered/missing."""
        return self.template_manifest.verify_template_files(loader)

    def map_record(self, record: dict, envelope: ExecutionEnvelope):
        template_id = record.get("template-id") or record.get("templateID")
        if not template_id:
            raise SchemaMismatch("nuclei result has no template-id")
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        protocol = record.get("type") or ""

        verdict = self.template_manifest.validate(str(template_id), protocol=str(protocol))
        if not verdict.ok:
            # A result from a template we did not approve (or a prohibited protocol)
            # is blocking: the run is not trustworthy and the task is quarantined.
            self._rejected[verdict.reason] = self._rejected.get(verdict.reason, 0) + 1
            return (EventKind.DIAGNOSTIC,
                    {"code": verdict.reason, "message": f"rejected template {template_id}",
                     "template_id": str(template_id), "protocol": protocol, "blocking": True}, 0.0)

        entry = self.template_manifest.entries[str(template_id)]
        self._findings += 1
        data = {
            "template_id": str(template_id),
            "template_commit": self.template_manifest.template_commit,
            "severity": info.get("severity") or entry.severity,
            "name": info.get("name") or "",
            "tags": info.get("tags") or list(entry.tags),
            "protocol": protocol,
            "matched_at": record.get("matched-at") or record.get("matched_at") or "",
            "matcher": record.get("matcher-name") or record.get("matcher_name") or "",
            "host": record.get("host") or envelope.target,
            # Candidate, never a finding: needs the evidence/verification pipeline.
            "verified": False,
        }
        # Unverified by construction; severity does not raise it above a candidate.
        return (EventKind.FINDING, data, 0.5)

    def interpret_result(self, result, envelope: ExecutionEnvelope):
        event = super().interpret_result(result, envelope)
        event.data.update({
            "findings": self._findings,
            "rejected_templates": dict(self._rejected),
            "template_commit": self.template_manifest.template_commit,
        })
        if self._rejected:
            # Any rejected template means the run's template set was not trustworthy.
            event.data["status"] = "quarantined"
        return event


def _looks_local(template_id: str) -> bool:
    tid = str(template_id or "")
    return ("/" in tid or "\\" in tid or tid.endswith((".yaml", ".yml"))
            or tid.startswith(".") or ":" in tid)


def new_template_manifest(*, manifest_id: str, executable_digest: str, template_commit: str,
                          entries: list[TemplateEntry], trusted_signers,
                          allowed_protocols=DEFAULT_ALLOWED_PROTOCOLS, version: int = 1) -> TemplateManifest:
    return TemplateManifest(
        manifest_id=manifest_id, version=version, executable_digest=executable_digest,
        template_commit=template_commit, entries={e.template_id: e for e in entries},
        trusted_signers=frozenset(trusted_signers), allowed_protocols=frozenset(allowed_protocols),
        created_at=datetime.now(UTC).isoformat(),
    )
