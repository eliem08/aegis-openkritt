"""Stand up a disposable LOCAL application instance for evidence reproduction.

The launcher is deliberately opt-in because repository Compose files execute third-
party service definitions. Unlike the old implementation, it does not pick an unused
host port and merely hope the application is mapped there. It inspects the normalized
Compose model, selects an explicit web service/container port, writes a localhost-only
override, starts the project, polls readiness, captures logs on failure, and tears down
containers plus volumes.
"""
from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


class LocalInstanceError(RuntimeError):
    """The local instance could not be started safely."""


def _run(args, cwd=None, timeout=600):
    try:
        return subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True,
                              text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise LocalInstanceError("docker executable not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalInstanceError(f"docker timed out after {timeout}s") from exc


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def compose_file(repo_root: str | Path) -> Path | None:
    root = Path(repo_root)
    for name in ("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"):
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def has_compose(repo_root: str | Path) -> bool:
    return compose_file(repo_root) is not None


def _compose_model(root: Path, source: Path) -> dict:
    result = _run(["docker", "compose", "-f", str(source), "config", "--format", "json"],
                  cwd=root, timeout=90)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "compose config failed").strip()
        raise LocalInstanceError(f"could not inspect compose model: {detail.splitlines()[-1]}")
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LocalInstanceError("docker compose returned invalid JSON configuration") from exc
    if not isinstance(model.get("services"), dict) or not model["services"]:
        raise LocalInstanceError("compose model contains no services")
    return model


def _port_numbers(service: dict) -> list[int]:
    ports: list[int] = []
    for row in service.get("ports") or ():
        target = row.get("target") if isinstance(row, dict) else None
        if target is None and isinstance(row, str):
            target = row.rsplit(":", 1)[-1].split("/", 1)[0]
        try:
            port = int(target)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    for raw in service.get("expose") or ():
        try:
            port = int(str(raw).split("/", 1)[0])
        except ValueError:
            continue
        if port not in ports:
            ports.append(port)
    return ports


def select_web_service(model: dict, *, service_name: str | None = None,
                       container_port: int | None = None) -> tuple[str, int]:
    services: dict = model["services"]
    if service_name:
        if service_name not in services:
            raise LocalInstanceError(f"compose service {service_name!r} does not exist")
        candidates = [(service_name, services[service_name])]
    else:
        candidates = list(services.items())
        preferred = ("web", "app", "api", "server", "frontend", "backend")
        candidates.sort(key=lambda item: (
            0 if any(token in item[0].lower() for token in preferred) else 1,
            item[0],
        ))
    if container_port is not None:
        if not 1 <= int(container_port) <= 65535:
            raise LocalInstanceError("container_port must be between 1 and 65535")
        name, service = candidates[0]
        declared = _port_numbers(service)
        if declared and int(container_port) not in declared:
            raise LocalInstanceError(
                f"container port {container_port} is not declared by compose service {name!r}")
        return name, int(container_port)
    common = (8080, 8000, 3000, 5000, 80, 443)
    for name, service in candidates:
        declared = _port_numbers(service)
        for port in common:
            if port in declared:
                return name, port
        if declared:
            return name, declared[0]
    raise LocalInstanceError(
        "could not identify a web service/port; pass service_name and container_port explicitly")


def _write_override(root: Path, service: str, host_port: int, container_port: int) -> Path:
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="aegis-compose-", suffix=".yml",
        dir=root, delete=False,
    )
    try:
        handle.write("services:\n")
        handle.write(f"  {service}:\n")
        handle.write("    ports:\n")
        handle.write(f'      - "127.0.0.1:{host_port}:{container_port}"\n')
    finally:
        handle.close()
    return Path(handle.name)


def wait_for_http(url: str, *, timeout: float = 120.0, interval: float = 3.0) -> bool:
    import httpx
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=5)
            return True
        except Exception:
            time.sleep(interval)
    return False


@dataclass
class LocalInstance:
    base_url: str
    project: str
    repo_root: Path
    compose_files: tuple[Path, ...] = ()
    service_name: str = ""
    container_port: int = 0
    _up: bool = False

    def _compose_args(self) -> list[str]:
        args = ["docker", "compose"]
        for path in self.compose_files:
            args.extend(["-f", str(path)])
        return args

    def logs(self, *, tail: int = 200) -> str:
        if not self._up:
            return ""
        result = _run([*self._compose_args(), "-p", self.project, "logs", "--no-color",
                       "--tail", str(tail)], cwd=self.repo_root, timeout=60)
        return (result.stdout or result.stderr or "").strip()

    def down(self) -> None:
        if self._up:
            _run([*self._compose_args(), "-p", self.project, "down", "-v", "--remove-orphans"],
                 cwd=self.repo_root, timeout=180)
            self._up = False
        for path in self.compose_files[1:]:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.down()


def start_local_instance(repo_root: str | Path, *, allow_compose_up: bool = False,
                         host_port: int | None = None, service_name: str | None = None,
                         container_port: int | None = None, ready_path: str = "/",
                         ready_timeout: float = 120.0) -> LocalInstance:
    root = Path(repo_root).resolve()
    if not allow_compose_up:
        raise LocalInstanceError(
            "compose bring-up is opt-in: pass allow_compose_up=True for a disposable local instance")
    source = compose_file(root)
    if source is None:
        raise LocalInstanceError("no docker-compose file found in the checkout")
    model = _compose_model(root, source)
    service, target_port = select_web_service(
        model, service_name=service_name, container_port=container_port)
    port = host_port or _free_port()
    project = f"aegis-repro-{port}"
    override = _write_override(root, service, port, target_port)
    instance = LocalInstance(
        base_url=f"http://127.0.0.1:{port}", project=project, repo_root=root,
        compose_files=(source, override), service_name=service, container_port=target_port,
    )
    result = _run([*instance._compose_args(), "-p", project, "up", "-d", "--remove-orphans"],
                  cwd=root, timeout=600)
    if result.returncode != 0:
        instance.down()
        detail = (result.stderr or result.stdout or "compose up failed").strip().splitlines()
        raise LocalInstanceError(f"compose up failed: {detail[-1] if detail else ''}")
    instance._up = True
    if not wait_for_http(instance.base_url + ready_path, timeout=ready_timeout):
        logs = instance.logs(tail=80)
        instance.down()
        suffix = f"; recent logs: {logs[-800:]}" if logs else ""
        raise LocalInstanceError(
            f"instance did not become ready at {instance.base_url}{ready_path} within "
            f"{ready_timeout:.0f}s{suffix}")
    return instance
