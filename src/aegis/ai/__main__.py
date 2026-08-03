"""Safe diagnostics for the optional DeepSeek integration."""

from __future__ import annotations

import argparse
import json
import sys

from aegis.env import load_dotenv

from .client import DeepSeekClient, DeepSeekError
from .config import DeepSeekAuthError, DeepSeekConfig, DeepSeekConfigError


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def doctor(argv=None, *, env=None, client_factory=DeepSeekClient) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.ai doctor")
    parser.add_argument("--live", action="store_true", help="make one paid synthetic request")
    args = parser.parse_args(list(argv or []))

    try:
        config = DeepSeekConfig.from_env(env)
    except DeepSeekAuthError:
        _emit({"live": bool(args.live), "status": "not_configured"})
        return 2 if args.live else 0
    except DeepSeekConfigError:
        _emit({"live": bool(args.live), "status": "invalid_config"})
        return 2

    if not args.live:
        _emit({"live": False, "model": config.model, "status": "configured"})
        return 0

    client = client_factory(config)
    try:
        result = client.complete_result(
            [
                {"role": "system", "content": "Return strict json only."},
                {
                    "role": "user",
                    "content": (
                        'Return exactly this json object: '
                        '{"aegis_deepseek_live":true}'
                    ),
                },
            ],
            json_mode=True,
            max_tokens=512,
        )
        try:
            parsed = json.loads(result.content)
        except (TypeError, json.JSONDecodeError):
            _emit({"live": True, "status": "invalid_response"})
            return 1
        if parsed != {"aegis_deepseek_live": True}:
            _emit({"live": True, "status": "invalid_response"})
            return 1
        _emit({
            "live": True,
            "model": result.model,
            "status": "ok",
            "latency_ms": result.latency_ms,
            "usage": result.usage,
        })
        return 0
    except DeepSeekError:
        _emit({"live": True, "status": "provider_error"})
        return 1
    finally:
        client.close()


def main(argv=None) -> int:
    load_dotenv()
    args = list(sys.argv[1:] if argv is None else argv)
    command = args.pop(0) if args else "doctor"
    if command != "doctor":
        print("usage: python -m aegis.ai doctor [--live]", file=sys.stderr)
        return 2
    return doctor(args)


if __name__ == "__main__":
    raise SystemExit(main())
