"""Stand up a throwaway LOCAL instance of a cloned repo for the reproduction agent.

The reproduction literature is blunt: autonomous deployment is a top blocker, and no
running instance means no trigger. When a cloned repo ships a docker-compose, Aegis
can bring up a disposable local instance, hand its URL to the reproduction agent, and
tear it down afterwards — turning "candidate" into "locally reproduced" without a
human hand-standing every target.

Hard boundaries:
* **Local only.** Binds to localhost; the agent's own guard still refuses anything
  non-loopback. Never a remote host.
* **Disposable.** Brought up in an isolated project name and torn down with volumes,
  so nothing persists.
* **Opt-in + guarded.** Requires an explicit ``allow_compose_up`` and a working
  ``docker``; degrades to "no instance" rather than doing anything surprising.

Nothing here touches a third party. It runs the project's own compose, unmodified.
"""

from __future__ import annotations

import socket
import subprocess
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


class LocalInstanceError(RuntimeError):
    """The local instance could not be started."""


def _run(args, cwd=None, timeout=600):
    try:
        return subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True,
                              text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise LocalInstanceError("docker executable not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalInstanceError(f"docker timed out after {timeout}s") from exc


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def has_compose(repo_root: str | Path) -> bool:
    root = Path(repo_root)
    return (root / "docker-compose.yml").is_file() or (root / "docker-compose.yaml").is_file()


def wait_for_http(url: str, *, timeout: float = 120.0, interval: float = 3.0) -> bool:
    """Poll until the instance answers (any HTTP status) or the timeout elapses."""
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
    _up: bool = False

    def down(self) -> None:
        """Tear down containers and volumes for this disposable project."""
        if not self._up:
            return
        _run(["docker", "compose", "-p", self.project, "down", "-v", "--remove-orphans"],
             cwd=self.repo_root, timeout=180)
        self._up = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.down()


def start_local_instance(repo_root: str | Path, *, allow_compose_up: bool = False,
                         host_port: int | None = None, ready_path: str = "/",
                         ready_timeout: float = 120.0) -> LocalInstance:
    """Bring up the repo's docker-compose as a disposable local instance.

    Refuses unless ``allow_compose_up`` is explicitly set — running arbitrary compose
    executes third-party service definitions, so it is never implicit. Returns a
    LocalInstance whose ``base_url`` is localhost; caller must ``down()`` (or use it as
    a context manager).
    """
    root = Path(repo_root)
    if not allow_compose_up:
        raise LocalInstanceError(
            "compose bring-up is opt-in: pass allow_compose_up=True to run the repo's "
            "own docker-compose as a disposable local instance"
        )
    if not has_compose(root):
        raise LocalInstanceError("no docker-compose file found in the checkout")

    port = host_port or _free_port()
    project = f"aegis-repro-{port}"
    # COMPOSE will map the project's exposed ports; we surface a localhost URL. The
    # caller/operator is responsible for a compose that exposes a web port.
    result = _run(["docker", "compose", "-p", project, "up", "-d"], cwd=root, timeout=600)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "compose up failed").strip().splitlines()
        raise LocalInstanceError(f"compose up failed: {detail[-1] if detail else ''}")

    instance = LocalInstance(base_url=f"http://127.0.0.1:{port}", project=project,
                             repo_root=root, _up=True)
    if not wait_for_http(instance.base_url + ready_path, timeout=ready_timeout):
        instance.down()
        raise LocalInstanceError(
            f"instance did not become ready at {instance.base_url}{ready_path} within "
            f"{ready_timeout:.0f}s (the compose may not expose {port}, or needs a manual port map)"
        )
    return instance
