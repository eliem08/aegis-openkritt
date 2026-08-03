from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from aegis.coord.redis_backend import RedisBackend

from .app import EgressServiceConfig, create_egress_app


def _secret(path_name: str) -> str:
    path = os.environ.get(path_name)
    if not path or not Path(path).is_file():
        raise RuntimeError(f"{path_name} is required")
    return Path(path).read_text(encoding="utf-8").strip()


def factory():
    redis_url = _secret("AEGIS_REDIS_URL_FILE")
    backend = RedisBackend(redis_url, namespace=os.environ.get("AEGIS_COORD_NAMESPACE", "aegis-prod"))
    return create_egress_app(EgressServiceConfig.from_env(), budget_backend=backend)


def main() -> None:
    uvicorn.run(
        "aegis.egress.__main__:factory", factory=True, host="0.0.0.0",
        port=int(os.environ.get("AEGIS_PORT", "8080")), proxy_headers=False, server_header=False,
    )


if __name__ == "__main__":
    main()
