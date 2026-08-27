"""Domain, wildcard, IP, and CIDR techniques — passive first, then bounded active work.

Ordering is deliberate and matches how the operator works a network asset: learn
from public records before touching the target, then make the smallest number of
requests that can actually distinguish a real weakness from a look-alike.

Certificate transparency is the one lane that contacts a host which is *not* the
target. It runs on a separate session bound to a fixed research-infrastructure
allowlist (``crt.sh`` only), so the program's own allowlist never has to be widened
and every CT lookup is still audited. Names the log returns are filtered back
through the program allowlist before anything else touches them.
"""

from __future__ import annotations

import json
import socket
import ssl
import xml.etree.ElementTree as ElementTree
from datetime import UTC, datetime
from typing import Any, Iterable

from .context import LaneContext
from .results import Observation, TechniqueResult, deduplicate, executed, now, unavailable
from .scope import OutOfScopeError, build_allowlist
from .session import BudgetExhausted, HuntSession

#: The only third-party host any passive lane may contact.
CT_LOG_HOST = "crt.sh"

#: Provider fingerprints for dangling-CNAME takeover. A match is a *candidate*: the
#: response body fingerprint must also be seen before it is reported, because a
#: CNAME to a provider is normal and only an unclaimed one is a finding.
TAKEOVER_FINGERPRINTS: tuple[tuple[str, str, str], ...] = (
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokudns.com", "No such app", "Heroku"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("s3.amazonaws.com", "NoSuchBucket", "Amazon S3"),
    ("cloudfront.net", "Bad request", "Amazon CloudFront"),
    ("azurewebsites.net", "Error 404 - Web app not found", "Azure App Service"),
    ("cloudapp.azure.com", "404 Web Site not found", "Azure"),
    ("trafficmanager.net", "404 Web Site not found", "Azure Traffic Manager"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("pantheonsite.io", "The gods are wise", "Pantheon"),
    ("wpengine.com", "The site you were looking for couldn't be found", "WP Engine"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("readthedocs.io", "unknown to Read the Docs", "Read the Docs"),
    ("surge.sh", "project not found", "Surge"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("shopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("netlify.app", "Not Found - Request ID", "Netlify"),
)

#: Headers whose absence is worth reporting, with the severity the operator would
#: actually claim. Nothing here is above "low" on its own — a missing header is a
#: hardening gap, not an exploitable bug, and inflating it burns program goodwill.
_SECURITY_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("strict-transport-security", "low", "Transport downgrade is not prevented over HTTPS"),
    ("content-security-policy", "low", "No script-source restriction to blunt injected markup"),
    ("x-content-type-options", "info", "MIME sniffing is not disabled"),
    ("x-frame-options", "info", "Framing is not restricted (CSP frame-ancestors may cover this)"),
    ("referrer-policy", "info", "Referrer leakage to third parties is unrestricted"),
)

#: Host names probed for a virtual host that the public name does not serve.
_VHOST_CANDIDATES = (
    "admin", "internal", "staging", "dev", "test", "api-internal", "jenkins", "grafana",
)


def _passive_session(context: LaneContext) -> HuntSession:
    """A session that may reach public research infrastructure and nothing else."""
    return HuntSession(
        allowlist=build_allowlist(
            program="aegis-passive-sources", in_scope=[CT_LOG_HOST],
            notes={"purpose": "public certificate transparency lookup only"},
        ),
        rate_limit=context.session.rate_limit,
        allow_state_change=False,
        log_path=context.session.log_path,
        transport=context.session.transport,
        sleep=context.session.sleep,
        clock=context.session.clock,
    )


def _apex(asset: str) -> str:
    value = asset.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    value = value.split("/", 1)[0].split(":", 1)[0]
    return value[2:] if value.startswith("*.") else value


# --------------------------------------------------------------------------- CT

def certificate_transparency(context: LaneContext) -> TechniqueResult:
    """Enumerate names from public CT logs, filtered back through the program scope."""
    technique = "passive-certificate-transparency"
    started = now()
    apex = _apex(context.asset)
    if not apex or apex.replace(".", "").isdigit():
        return unavailable(
            technique, context.asset,
            "certificate transparency is keyed on domain names; this asset is an address",
        )
    session = _passive_session(context)
    url = f"https://{CT_LOG_HOST}/?q=%25.{apex}&output=json"
    try:
        response = session.get(url, technique_id=technique)
    except (OutOfScopeError, BudgetExhausted, OSError) as exc:
        return unavailable(
            technique, context.asset,
            f"certificate transparency lookup did not complete: {type(exc).__name__}: {exc}",
            tool=CT_LOG_HOST,
        )
    if response.status_code != 200:
        return unavailable(
            technique, context.asset,
            f"{CT_LOG_HOST} returned HTTP {response.status_code}", tool=CT_LOG_HOST,
        )
    names = parse_crtsh(response.text)
    in_scope = sorted(name for name in names if context.session.allowlist.is_allowed(name))
    out_of_scope = sorted(set(names) - set(in_scope))
    observations = [Observation(
        technique, "Certificate transparency exposed in-scope hostnames", "info",
        apex,
        evidence={"in_scope_names": in_scope[:200], "in_scope_count": len(in_scope)},
        weakness="attack-surface-inventory",
        recommendation="feed these names back through the hunt as individual assets",
    )] if in_scope else []
    return executed(
        technique, context.asset, observations, tool=CT_LOG_HOST,
        requests_made=1, started_at=started,
        metadata={
            "total_names": len(names),
            "in_scope_names": len(in_scope),
            "excluded_by_scope": len(out_of_scope),
        },
    )


def parse_crtsh(payload: str) -> tuple[str, ...]:
    """Extract unique lowercase hostnames from a crt.sh JSON response.

    crt.sh puts multiple SANs in ``name_value`` separated by newlines and emits
    wildcard entries; both are normalized here. Malformed payloads yield nothing
    rather than raising, because a log outage must not look like a scan failure.
    """
    try:
        entries = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return ()
    if not isinstance(entries, list):
        return ()
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for field_name in ("name_value", "common_name"):
            raw = entry.get(field_name)
            if not isinstance(raw, str):
                continue
            for line in raw.replace(",", "\n").splitlines():
                candidate = line.strip().lower().lstrip("*.").rstrip(".")
                if candidate and "@" not in candidate and " " not in candidate:
                    names.add(candidate)
    return tuple(sorted(names))


# ------------------------------------------------------------------------- DNS

def _resolver():
    """Return a dnspython resolver module, or ``None`` when it is not installed."""
    try:  # pragma: no cover - import availability is environment-specific
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError:
        return None
    return dns.resolver


def dns_enumeration(context: LaneContext) -> TechniqueResult:
    """Resolve the record types that describe an asset's real infrastructure."""
    technique = "dns-enumeration"
    started = now()
    name = _apex(context.asset)
    try:
        context.session.authorize_connection(name, technique_id=technique, protocol="DNS")
    except (OutOfScopeError, BudgetExhausted) as exc:
        return unavailable(technique, context.asset, str(exc))

    records: dict[str, list[str]] = {}
    resolver = _resolver()
    if resolver is None:
        try:
            infos = socket.getaddrinfo(name, None)
        except OSError as exc:
            return unavailable(
                technique, context.asset, f"name did not resolve: {exc}",
                tool="stdlib-resolver",
            )
        records["A"] = sorted({
            info[4][0] for info in infos if info[0] is socket.AF_INET
        })
        records["AAAA"] = sorted({
            info[4][0] for info in infos if info[0] is socket.AF_INET6
        })
        return executed(
            technique, context.asset, (), tool="stdlib-resolver", started_at=started,
            reason=(
                "dnspython is not installed, so only address records were resolved; "
                "install the `dnspython` package for CNAME/MX/TXT/NS coverage"
            ),
            metadata={"records": {k: v for k, v in records.items() if v}, "degraded": True},
        )

    for record_type in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
        try:
            answers = resolver.resolve(name, record_type, lifetime=10.0)
        except Exception:  # noqa: BLE001 - every resolver error means "no data here"
            continue
        records[record_type] = sorted(str(item).strip().rstrip(".") for item in answers)

    if not records:
        return unavailable(
            technique, context.asset, "no DNS records resolved for this name",
            tool="dnspython",
        )
    observations = []
    for value in records.get("TXT", ()):  # cheap, high-signal: keys pasted into TXT
        lowered = value.lower()
        if any(token in lowered for token in ("aws_secret", "api_key", "password=")):
            observations.append(Observation(
                technique, "Credential-shaped material published in a DNS TXT record",
                "medium", name, evidence={"record_type": "TXT"},
                weakness="information-disclosure",
                recommendation="confirm the value is live before reporting",
            ))
    return executed(
        technique, context.asset, observations, tool="dnspython", started_at=started,
        metadata={"records": records},
    )


def subdomain_takeover(context: LaneContext) -> TechniqueResult:
    """Report a CNAME to an unclaimed provider, confirmed by the provider's own body.

    A CNAME alone is not a finding — pointing at a CDN is normal. This reports only
    when the delegation target matches a known provider *and* the provider returns
    its "this name is not claimed" body, which is the contrast that separates a real
    takeover from ordinary hosting.
    """
    technique = "subdomain-takeover"
    started = now()
    name = _apex(context.asset)
    resolver = _resolver()
    if resolver is None:
        return unavailable(
            technique, context.asset,
            "CNAME inspection requires the `dnspython` package, which is not installed; "
            "install it to enable takeover detection",
            tool="dnspython",
        )
    try:
        context.session.authorize_connection(name, technique_id=technique, protocol="DNS")
        answers = resolver.resolve(name, "CNAME", lifetime=10.0)
    except (OutOfScopeError, BudgetExhausted) as exc:
        return unavailable(technique, context.asset, str(exc))
    except Exception:  # noqa: BLE001 - no CNAME is the common, uninteresting case
        return executed(
            technique, context.asset, (), tool="dnspython", started_at=started,
            metadata={"cname": None, "verdict": "no CNAME delegation present"},
        )

    targets = [str(item).strip().rstrip(".").lower() for item in answers]
    observations: list[Observation] = []
    for target in targets:
        provider = next(
            (item for item in TAKEOVER_FINGERPRINTS if target.endswith(item[0])), None,
        )
        if provider is None:
            continue
        suffix, marker, label = provider
        try:
            response = context.session.get(
                f"https://{name}/", technique_id=technique,
            )
        except (OutOfScopeError, BudgetExhausted, OSError) as exc:
            observations.append(Observation(
                technique, "Delegation to a takeover-prone provider could not be confirmed",
                "info", name,
                evidence={"cname": target, "provider": label,
                          "confirmation_error": f"{type(exc).__name__}: {exc}"},
                weakness="dangling-delegation",
                recommendation="confirm manually before reporting; unconfirmed is not a finding",
            ))
            continue
        if marker.lower() in response.text.lower():
            observations.append(Observation(
                technique, f"Dangling CNAME to an unclaimed {label} resource", "high", name,
                evidence={"cname": target, "provider": label, "provider_suffix": suffix,
                          "status_code": response.status_code, "body_marker": marker},
                guarded_sibling=(
                    "sibling names on the same provider return their tenant content; "
                    "only this one returns the provider's unclaimed-resource page"
                ),
                weakness="subdomain-takeover",
                recommendation="claim the resource on the provider to prove control, "
                               "then report with the claim as evidence",
            ))
    return executed(
        technique, context.asset, deduplicate(observations), tool="dnspython",
        started_at=started, metadata={"cname_targets": targets},
    )


# --------------------------------------------------------------------- Services

def service_identification(context: LaneContext) -> TechniqueResult:
    """Bounded top-port service and version fingerprinting via nmap."""
    technique = "service-identification"
    started = now()
    target = _apex(context.asset)
    tool = context.resolver.resolve("nmap", version_flag="--version")
    if not tool.usable:
        return unavailable(
            technique, context.asset,
            f"nmap is required for service identification but is unavailable: {tool.reason}",
            tool="nmap",
        )
    try:
        context.session.authorize_connection(target, technique_id=technique, protocol="TCP")
    except (OutOfScopeError, BudgetExhausted) as exc:
        return unavailable(technique, context.asset, str(exc), tool="nmap")

    code, stdout, stderr = context.resolver.run(
        tool,
        ["-sV", "--version-light", "-T2", "--top-ports", "100", "-oX", "-", target],
        timeout=600.0,
    )
    if code != 0 and not stdout.strip():
        return unavailable(
            technique, context.asset, f"nmap did not complete: {stderr.strip()[:400]}",
            tool="nmap", metadata={"exit_code": code},
        )
    services = parse_nmap_xml(stdout)
    observations = [
        Observation(
            technique, f"Exposed {item['service']} service on port {item['port']}",
            "info", f"{target}:{item['port']}",
            evidence=dict(item), weakness="exposed-service",
            recommendation="confirm the service is intended to be internet-facing",
        )
        for item in services if item.get("state") == "open"
    ]
    return executed(
        technique, context.asset, observations, tool="nmap", tool_version=tool.version,
        started_at=started, metadata={"services": services, "location": tool.location.value},
    )


def parse_nmap_xml(payload: str) -> tuple[dict[str, Any], ...]:
    """Extract open ports and service metadata from nmap's XML output."""
    if not payload.strip():
        return ()
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return ()
    rows: list[dict[str, Any]] = []
    for port in root.iter("port"):
        state = port.find("state")
        service = port.find("service")
        rows.append({
            "port": int(port.get("portid") or 0),
            "protocol": port.get("protocol") or "",
            "state": (state.get("state") if state is not None else "") or "",
            "service": (service.get("name") if service is not None else "") or "unknown",
            "product": (service.get("product") if service is not None else "") or "",
            "version": (service.get("version") if service is not None else "") or "",
        })
    return tuple(rows)


# -------------------------------------------------------------------------- TLS

def tls_inspection(context: LaneContext) -> TechniqueResult:
    """Inspect the served certificate and negotiated protocol on a single handshake."""
    technique = "tls-inspection"
    started = now()
    host = _apex(context.asset)
    port = int(context.option("tls_port", 443))
    try:
        context.session.authorize_connection(
            f"{host}:{port}", technique_id=technique, protocol="TLS",
        )
    except (OutOfScopeError, BudgetExhausted) as exc:
        return unavailable(technique, context.asset, str(exc))

    ssl_context = ssl.create_default_context()
    # Report what is actually served, including a mismatched or expired certificate,
    # which strict verification would turn into an exception instead of evidence.
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=15.0) as raw:
            with ssl_context.wrap_socket(raw, server_hostname=host) as tls:
                certificate = tls.getpeercert(binary_form=False) or {}
                der = tls.getpeercert(binary_form=True) or b""
                protocol = tls.version() or ""
                cipher = tls.cipher() or ("", "", 0)
    except (OSError, ssl.SSLError) as exc:
        return unavailable(
            technique, context.asset, f"TLS handshake failed: {type(exc).__name__}: {exc}",
            tool="stdlib-ssl",
        )

    summary = summarize_certificate(certificate, host)
    observations: list[Observation] = []
    if protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
        observations.append(Observation(
            technique, f"Deprecated TLS protocol negotiated ({protocol})", "low",
            f"{host}:{port}", evidence={"protocol": protocol, "cipher": cipher[0]},
            weakness="weak-transport-security",
            recommendation="report as a hardening issue, not as a break of confidentiality",
        ))
    if summary["expired"]:
        observations.append(Observation(
            technique, "Served certificate is expired", "low", f"{host}:{port}",
            evidence={"not_after": summary["not_after"]},
            weakness="expired-certificate",
            recommendation="low impact unless the host handles authenticated traffic",
        ))
    if summary["hostname_mismatch"]:
        observations.append(Observation(
            technique, "Served certificate does not cover the requested hostname", "low",
            f"{host}:{port}",
            evidence={"subject_alt_names": summary["subject_alt_names"][:50]},
            weakness="certificate-hostname-mismatch",
            recommendation="often a shared-hosting artifact; confirm before reporting",
        ))
    return executed(
        technique, context.asset, observations, tool="stdlib-ssl", started_at=started,
        metadata={
            "protocol": protocol, "cipher": cipher[0], "certificate": summary,
            "certificate_bytes": len(der),
        },
    )


def summarize_certificate(certificate: dict[str, Any], host: str) -> dict[str, Any]:
    """Normalize a parsed peer certificate into the facts the lane reasons about."""
    names = sorted({
        str(value).lower() for key, value in certificate.get("subjectAltName", ())
        if key.lower() == "dns"
    })
    not_after = str(certificate.get("notAfter") or "")
    expired = False
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            expired = expiry < datetime.now(UTC)
        except ValueError:
            expired = False
    return {
        "subject_alt_names": names,
        "not_before": str(certificate.get("notBefore") or ""),
        "not_after": not_after,
        "issuer": _flatten_name(certificate.get("issuer", ())),
        "subject": _flatten_name(certificate.get("subject", ())),
        "expired": expired,
        "hostname_mismatch": bool(names) and not _covers(names, host),
    }


def _flatten_name(value: Iterable[Any]) -> dict[str, str]:
    flat: dict[str, str] = {}
    for group in value or ():
        for pair in group or ():
            if isinstance(pair, tuple) and len(pair) == 2:
                flat[str(pair[0])] = str(pair[1])
    return flat


def _covers(names: Iterable[str], host: str) -> bool:
    target = host.lower()
    for name in names:
        if name == target:
            return True
        if name.startswith("*.") and target.endswith(name[1:]) and \
                target.count(".") == name.count("."):
            return True
    return False


# ------------------------------------------------------------------------ HTTP

def security_headers(context: LaneContext) -> TechniqueResult:
    """Read the response header posture from a single GET."""
    technique = "security-headers"
    started = now()
    url = context.base_url() + "/"
    try:
        response = context.session.get(url, technique_id=technique)
    except (OutOfScopeError, BudgetExhausted, OSError) as exc:
        return unavailable(
            technique, context.asset,
            f"header analysis did not complete: {type(exc).__name__}: {exc}",
            tool="stdlib-http",
        )
    present = {key.lower(): value for key, value in response.headers.items()}
    observations = [
        Observation(
            technique, f"Missing {name} response header", severity, url,
            evidence={"status_code": response.status_code, "header": name},
            weakness="missing-security-header", recommendation=note,
        )
        for name, severity, note in _SECURITY_HEADERS if name not in present
    ]
    server = present.get("server", "")
    if server and any(char.isdigit() for char in server):
        observations.append(Observation(
            technique, "Server banner discloses a precise software version", "info", url,
            evidence={"server": server}, weakness="version-disclosure",
            recommendation="only useful paired with a known CVE for that exact version",
        ))
    return executed(
        technique, context.asset, deduplicate(observations), tool="stdlib-http",
        requests_made=1, started_at=started,
        metadata={"status_code": response.status_code, "headers_present": sorted(present)},
    )


def virtual_host_discovery(context: LaneContext) -> TechniqueResult:
    """Find vhosts the public name does not serve, using a differential baseline.

    A candidate only counts when its response *differs materially* from the
    baseline the same IP returns for an intentionally bogus Host header. Without
    that contrast, a catch-all vhost makes every candidate look like a hit.
    """
    technique = "virtual-host-discovery"
    started = now()
    apex = _apex(context.asset)
    url = context.base_url() + "/"
    try:
        control = context.session.get(
            url, technique_id=technique,
            host_override=f"aegis-nonexistent-baseline.{apex}",
        )
    except (OutOfScopeError, BudgetExhausted, OSError) as exc:
        return unavailable(
            technique, context.asset,
            f"baseline request failed, so no differential is possible: {exc}",
            tool="stdlib-http",
        )
    baseline = (control.status_code, len(control.body))
    candidates = tuple(context.option("vhost_candidates", _VHOST_CANDIDATES))
    observations: list[Observation] = []
    probed = 0
    for label in candidates:
        candidate = f"{label}.{apex}"
        try:
            response = context.session.get(
                url, technique_id=technique, host_override=candidate,
            )
        except BudgetExhausted:
            break
        except (OutOfScopeError, OSError):
            continue
        probed += 1
        signature = (response.status_code, len(response.body))
        if signature == baseline:
            continue
        observations.append(Observation(
            technique, f"Virtual host {candidate} serves different content", "info", candidate,
            evidence={
                "status_code": response.status_code,
                "response_bytes": len(response.body),
                "baseline_status_code": control.status_code,
                "baseline_bytes": len(control.body),
            },
            guarded_sibling=(
                "a bogus Host header on the same address returns "
                f"HTTP {control.status_code}/{len(control.body)} bytes"
            ),
            weakness="unlinked-virtual-host",
            recommendation="check the vhost is in scope before probing it further",
        ))
    return executed(
        technique, context.asset, deduplicate(observations), tool="stdlib-http",
        requests_made=probed + 1, started_at=started,
        metadata={"baseline": {"status_code": baseline[0], "bytes": baseline[1]},
                  "candidates_probed": probed},
    )


__all__ = [
    "CT_LOG_HOST",
    "TAKEOVER_FINGERPRINTS",
    "certificate_transparency",
    "dns_enumeration",
    "parse_crtsh",
    "parse_nmap_xml",
    "security_headers",
    "service_identification",
    "subdomain_takeover",
    "summarize_certificate",
    "tls_inspection",
    "virtual_host_discovery",
]
