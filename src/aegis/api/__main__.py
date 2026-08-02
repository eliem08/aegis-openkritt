"""Run the control plane:  python -m aegis.api

Configuration is read from the environment (see aegis.api.config):
  AEGIS_API_KEYS         JSON {token: "operator"|"agent"} (or {token:{name,role}})
  AEGIS_SIGNING_KEYS     JSON {key_id: secret}
  AEGIS_REQUIRE_SIGNATURE  "1" (default) / "0"
  AEGIS_AUTH_DISABLED    "1" to disable auth (dev only)
  AEGIS_HOST / AEGIS_PORT  bind address (default 127.0.0.1:8000)
"""

from __future__ import annotations

import os

import uvicorn

from ..env import load_dotenv
from .app import create_app
from .config import ControlPlaneConfig
from .observability import configure_logging


def main() -> None:
    configure_logging()
    load_dotenv()  # pick up a local .env if present (real env still wins)
    config = ControlPlaneConfig.from_env()
    app = create_app(config)
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    port = int(os.environ.get("AEGIS_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
