"""Persist a fresh, provenance-rich HackerOne program snapshot using GET requests only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dotenv import dotenv_values

from aegis.ingest.hackerone import HackerOneClient, map_program
from aegis.ingest.source import ProgramSnapshot


def _exclusive_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handle")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--output-dir", default="reports/operator-input")
    parser.add_argument("--valid-minutes", type=int, default=60)
    args = parser.parse_args(argv)
    if not 1 <= args.valid_minutes <= 60:
        raise SystemExit("snapshot validity must be between 1 and 60 minutes")
    environment = {**os.environ, **{
        key: value for key, value in dotenv_values(args.env_file).items() if value is not None
    }}
    observed = datetime.now(UTC)
    with HackerOneClient.from_env(environment) as client:
        program = client.get_program(args.handle)
        scopes = client.get_structured_scopes(args.handle)
    authoritative = {"program": program.get("data", program), "structured_scopes": scopes}
    raw = json.dumps(authoritative, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    source_hash = hashlib.sha256(raw.encode()).hexdigest()
    rules = map_program(program, scopes)
    if rules.handle != args.handle:
        raise SystemExit("HackerOne response handle does not match the requested program")
    snapshot = ProgramSnapshot(
        rules=rules,
        source=f"hackerone:api:{args.handle}",
        source_hash=source_hash,
        retrieved_at=observed,
        authorization_expires_at=observed + timedelta(minutes=args.valid_minutes),
    )
    stamp = observed.strftime("%Y%m%dT%H%M%SZ")
    output = Path(args.output_dir)
    authoritative_path = output / f"{args.handle}-authoritative-{stamp}.json"
    snapshot_path = output / f"{args.handle}-snapshot-{stamp}.json"
    _exclusive_json(authoritative_path, authoritative)
    _exclusive_json(snapshot_path, snapshot.model_dump(mode="json"))
    print(json.dumps({
        "handle": args.handle,
        "source": snapshot.source,
        "source_hash": source_hash,
        "retrieved_at": snapshot.retrieved_at.isoformat(),
        "authorization_expires_at": snapshot.authorization_expires_at.isoformat(),
        "structured_scope_rows": len(scopes),
        "snapshot_path": str(snapshot_path),
        "authoritative_path": str(authoritative_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
