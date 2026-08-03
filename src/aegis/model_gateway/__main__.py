"""Run the dedicated model gateway."""

import uvicorn

from .config import ModelGatewayConfig
from .service import create_model_gateway_app


def factory():
    return create_model_gateway_app(ModelGatewayConfig.from_env())


def main() -> None:
    uvicorn.run(
        "aegis.model_gateway.__main__:factory",
        factory=True,
        host="0.0.0.0",
        port=8090,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
