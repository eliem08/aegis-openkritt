"""Offline surface correlation for a safely extracted firmware rootfs.

This module reads only the retained extraction directory. It never executes binaries/scripts and
never records secret values. It emits bounded path/hash metadata for web roots, service configs,
init mechanisms, package databases, TLS material presence, embedded ELF files, route-like strings
and listen-port hints so later research can prioritize high-value local evidence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from .safe_archive import SafeArchiveExtraction


class RootfsSurfaceError(RuntimeError):
    pass


@dataclass(frozen=True)
class SurfaceFile:
    path: str
    size_bytes: int
    sha256: str
    category: str


@dataclass(frozen=True)
class RootfsSurfaceReport:
    rootfs_digest: str
    scanned_files: int
    scanned_bytes: int
    web_files: tuple[SurfaceFile, ...]
    service_configs: tuple[SurfaceFile, ...]
    init_files: tuple[SurfaceFile, ...]
    package_databases: tuple[SurfaceFile, ...]
    tls_material: tuple[SurfaceFile, ...]
    elf_files: tuple[SurfaceFile, ...]
    route_hints: tuple[str, ...]
    listen_port_hints: tuple[int, ...]
    service_hints: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            **asdict(self),
            "web_files": [asdict(item) for item in self.web_files],
            "service_configs": [asdict(item) for item in self.service_configs],
            "init_files": [asdict(item) for item in self.init_files],
            "package_databases": [asdict(item) for item in self.package_databases],
            "tls_material": [asdict(item) for item in self.tls_material],
            "elf_files": [asdict(item) for item in self.elf_files],
        }


_WEB_EXTENSIONS = {
    ".html", ".htm", ".js", ".css", ".php", ".cgi", ".lua", ".asp", ".aspx", ".jsp",
}
_WEB_ROOT_PARTS = {"www", "htdocs", "web", "wwwroot", "cgi-bin"}
_CONFIG_NAMES = {
    "nginx.conf": "nginx",
    "httpd.conf": "httpd",
    "apache2.conf": "apache",
    "lighttpd.conf": "lighttpd",
    "uhttpd": "uhttpd",
    "uhttpd.conf": "uhttpd",
    "dnsmasq.conf": "dnsmasq",
    "sshd_config": "ssh",
    "dropbear": "dropbear-ssh",
    "mosquitto.conf": "mqtt",
    "smb.conf": "samba",
}
_PACKAGE_DATABASE_SUFFIXES = {
    "var/lib/dpkg/status",
    "lib/opkg/status",
    "var/lib/rpm/Packages",
    "var/lib/apk/db/installed",
}
_TLS_EXTENSIONS = {".pem", ".crt", ".cer", ".key", ".p12", ".pfx"}
_TEXT_EXTENSIONS = _WEB_EXTENSIONS | {
    ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml", ".sh", ".service",
}
_ROUTE_RE = re.compile(
    rb"(?<![A-Za-z0-9_])/(?:api|admin|cgi-bin|rpc|rest|graphql|upload|download|login|auth)"
    rb"(?:/[A-Za-z0-9._~!$&'()*+,;=:@%{}\-]+){0,5}"
)
_LISTEN_RE = re.compile(
    rb"(?i)(?:(?:listen|port)\s*[=: ]\s*|(?:-p|--port)\s+)([0-9]{1,5})"
)
_SERVICE_MARKERS = {
    b"dropbear": "dropbear-ssh",
    b"sshd": "ssh",
    b"telnetd": "telnet",
    b"uhttpd": "uhttpd",
    b"lighttpd": "lighttpd",
    b"nginx": "nginx",
    b"httpd": "httpd",
    b"dnsmasq": "dnsmasq",
    b"miniupnpd": "upnp",
    b"mosquitto": "mqtt",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_digest(rows: list[SurfaceFile]) -> str:
    material = "\n".join(
        f"{item.path}\0{item.size_bytes}\0{item.sha256}" for item in sorted(rows, key=lambda x: x.path)
    ).encode()
    return hashlib.sha256(material).hexdigest()


def _is_web(relative: str, path: Path) -> bool:
    parts = {part.lower() for part in Path(relative).parts}
    return path.suffix.lower() in _WEB_EXTENSIONS or bool(parts & _WEB_ROOT_PARTS)


def _service_config(relative: str, path: Path) -> str:
    name = path.name.lower()
    if name in _CONFIG_NAMES:
        return _CONFIG_NAMES[name]
    lowered = relative.lower()
    if "/etc/config/uhttpd" in "/" + lowered:
        return "uhttpd"
    if "/etc/config/dropbear" in "/" + lowered:
        return "dropbear-ssh"
    return ""


def _is_init(relative: str) -> bool:
    lowered = "/" + relative.lower().lstrip("/")
    return (
        "/etc/init.d/" in lowered
        or "/etc/rc.d/" in lowered
        or "/lib/systemd/system/" in lowered
        or lowered.endswith("/etc/inittab")
        or lowered.endswith("/sbin/init")
    )


def correlate_rootfs_surface(
    extraction: SafeArchiveExtraction,
    *,
    max_files: int = 20_000,
    max_total_bytes: int = 2 * 1024 * 1024 * 1024,
    max_text_file_bytes: int = 1024 * 1024,
    max_routes: int = 250,
) -> RootfsSurfaceReport:
    root = Path(extraction.root).resolve()
    if not root.is_dir():
        raise RootfsSurfaceError("extracted rootfs is unavailable")
    all_files: list[SurfaceFile] = []
    web: list[SurfaceFile] = []
    configs: list[SurfaceFile] = []
    init: list[SurfaceFile] = []
    packages: list[SurfaceFile] = []
    tls: list[SurfaceFile] = []
    elf: list[SurfaceFile] = []
    routes: set[str] = set()
    ports: set[int] = set()
    services: set[str] = set()
    scanned_bytes = 0

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RootfsSurfaceError("extracted rootfs contains a symlink")
        if not path.is_file():
            continue
        if len(all_files) >= max_files:
            raise RootfsSurfaceError("rootfs exceeds surface file-count limit")
        size = path.stat().st_size
        scanned_bytes += size
        if scanned_bytes > max_total_bytes:
            raise RootfsSurfaceError("rootfs exceeds surface byte limit")
        relative = path.relative_to(root).as_posix()
        digest = _sha256_file(path)
        base = SurfaceFile(relative, size, digest, "file")
        all_files.append(base)

        if _is_web(relative, path):
            web.append(SurfaceFile(relative, size, digest, "web"))
        service = _service_config(relative, path)
        if service:
            services.add(service)
            configs.append(SurfaceFile(relative, size, digest, "service_config"))
        is_init = _is_init(relative)
        if is_init:
            init.append(SurfaceFile(relative, size, digest, "init"))
        if relative in _PACKAGE_DATABASE_SUFFIXES:
            packages.append(SurfaceFile(relative, size, digest, "package_database"))
        if path.suffix.lower() in _TLS_EXTENSIONS:
            tls.append(SurfaceFile(relative, size, digest, "tls_material_presence"))

        prefix = b""
        if size:
            try:
                with path.open("rb") as handle:
                    prefix = handle.read(min(size, max_text_file_bytes))
            except OSError:
                prefix = b""
        if prefix.startswith(b"\x7fELF"):
            elf.append(SurfaceFile(relative, size, digest, "elf"))
        if size <= max_text_file_bytes and (
            path.suffix.lower() in _TEXT_EXTENSIONS or service or is_init
        ):
            lower = prefix.lower()
            for marker, label in _SERVICE_MARKERS.items():
                if marker in lower:
                    services.add(label)
            for match in _ROUTE_RE.finditer(prefix):
                if len(routes) >= max_routes:
                    break
                routes.add(match.group(0).decode("utf-8", errors="ignore")[:300])
            for match in _LISTEN_RE.finditer(prefix):
                try:
                    port = int(match.group(1))
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    ports.add(port)

    return RootfsSurfaceReport(
        rootfs_digest=_tree_digest(all_files),
        scanned_files=len(all_files),
        scanned_bytes=scanned_bytes,
        web_files=tuple(web[:1000]),
        service_configs=tuple(configs[:500]),
        init_files=tuple(init[:500]),
        package_databases=tuple(packages[:100]),
        tls_material=tuple(tls[:500]),
        elf_files=tuple(elf[:1000]),
        route_hints=tuple(sorted(routes)),
        listen_port_hints=tuple(sorted(ports)),
        service_hints=tuple(sorted(services)),
    )
