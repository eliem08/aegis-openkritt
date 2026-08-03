"""Create ignored model-gateway secrets without printing their values."""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path

from aegis.env import parse_env


class ModelSecretBootstrapError(RuntimeError):
    pass


def bootstrap_model_secrets(
    output: str | Path = "secrets",
    *,
    env_file: str | Path = ".env",
    force: bool = False,
) -> list[Path]:
    root = Path(output).resolve()
    source = Path(env_file)
    try:
        values = parse_env(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ModelSecretBootstrapError("cannot read the requested env file") from exc
    provider_key = values.get("DEEPSEEK_API_KEY", "").strip()
    if not provider_key or provider_key == "your-deepseek-api-key":
        raise ModelSecretBootstrapError("DEEPSEEK_API_KEY is not configured")

    root.mkdir(parents=True, exist_ok=True)
    outputs = {
        root / "deepseek_api_key": provider_key,
        root / "model_gateway_token": secrets.token_urlsafe(48),
    }
    for path in outputs:
        if path.exists() and not force:
            raise ModelSecretBootstrapError(f"refusing to overwrite {path.name}")
    for path, value in outputs.items():
        path.write_text(value, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return list(outputs)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="secrets")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    paths = bootstrap_model_secrets(
        args.output, env_file=args.env_file, force=args.force,
    )
    print(f"created {len(paths)} model secret files under {Path(args.output).resolve()}")
    print("secret values were not printed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
