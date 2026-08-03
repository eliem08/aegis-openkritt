"""Run the hardened control plane with ``python -m aegis.production``."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "aegis.production.app:create_production_app",
        factory=True,
        host=os.environ.get("AEGIS_HOST", "0.0.0.0"),
        port=int(os.environ.get("AEGIS_PORT", "8000")),
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
