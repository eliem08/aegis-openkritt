"""Encrypted PostgreSQL logical backup and archive verification."""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from cryptography.fernet import Fernet, InvalidToken

MAGIC = b"AEGISBK1"
CHUNK_SIZE = 1024 * 1024


class BackupError(RuntimeError):
    pass


def _pg_environment(dsn: str) -> tuple[dict[str, str], str]:
    parts = urlsplit(dsn)
    if parts.scheme not in {"postgres", "postgresql"} or not parts.hostname or not parts.path.strip("/"):
        raise BackupError("invalid PostgreSQL DSN")
    query = parse_qs(parts.query)
    env = dict(os.environ)
    env.update({
        "PGHOST": parts.hostname,
        "PGPORT": str(parts.port or 5432),
        "PGUSER": unquote(parts.username or ""),
        "PGPASSWORD": unquote(parts.password or ""),
        "PGDATABASE": parts.path.strip("/"),
        "PGSSLMODE": query.get("sslmode", ["verify-full"])[0],
    })
    if query.get("sslrootcert"):
        env["PGSSLROOTCERT"] = query["sslrootcert"][0]
    return env, env["PGDATABASE"]


def _key(path_text: str) -> Fernet:
    path = Path(path_text)
    try:
        return Fernet(path.read_bytes().strip())
    except (OSError, ValueError) as exc:
        raise BackupError("backup key file is missing or invalid") from exc


def encrypt_stream(source, destination, fernet: Fernet) -> str:
    digest = hashlib.sha256()
    destination.write(MAGIC)
    digest.update(MAGIC)
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            break
        token = fernet.encrypt(chunk)
        header = struct.pack(">I", len(token))
        destination.write(header)
        destination.write(token)
        digest.update(header)
        digest.update(token)
    return digest.hexdigest()


def decrypt_stream(source, destination, fernet: Fernet) -> None:
    if source.read(len(MAGIC)) != MAGIC:
        raise BackupError("backup magic is invalid")
    while True:
        header = source.read(4)
        if not header:
            break
        if len(header) != 4:
            raise BackupError("backup record is truncated")
        length = struct.unpack(">I", header)[0]
        if length <= 0 or length > CHUNK_SIZE * 2:
            raise BackupError("backup record length is invalid")
        token = source.read(length)
        if len(token) != length:
            raise BackupError("backup record is truncated")
        try:
            destination.write(fernet.decrypt(token))
        except InvalidToken as exc:
            raise BackupError("backup authentication failed") from exc


def create_backup(dsn: str, output: str, key_file: str, *, pg_dump="pg_dump") -> Path:
    destination = Path(output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise BackupError("refusing to overwrite an existing backup")
    env, database = _pg_environment(dsn)
    process = subprocess.Popen(
        [pg_dump, "--format=custom", "--no-owner", "--no-privileges", database],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    assert process.stdout is not None
    try:
        with destination.open("xb") as handle:
            checksum = encrypt_stream(process.stdout, handle, _key(key_file))
        stderr = process.communicate()[1]
        if process.returncode:
            destination.unlink(missing_ok=True)
            raise BackupError(f"pg_dump failed with exit code {process.returncode}: {stderr.decode(errors='replace')[:240]}")
    except Exception:
        process.kill()
        process.wait()
        destination.unlink(missing_ok=True)
        raise
    destination.with_suffix(destination.suffix + ".sha256").write_text(
        f"{checksum}  {destination.name}\n", encoding="ascii",
    )
    return destination


def verify_backup(path_text: str, key_file: str, *, pg_restore="pg_restore") -> None:
    path = Path(path_text).resolve()
    checksum_path = path.with_suffix(path.suffix + ".sha256")
    expected = checksum_path.read_text(encoding="ascii").split()[0]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise BackupError("encrypted backup checksum mismatch")
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(prefix="aegis-restore-", suffix=".dump", delete=False) as temp:
            temp_name = temp.name
            with path.open("rb") as source:
                decrypt_stream(source, temp, _key(key_file))
        result = subprocess.run(
            [pg_restore, "--list", temp_name], capture_output=True, check=False,
        )
        if result.returncode:
            raise BackupError(f"pg_restore archive validation failed with exit code {result.returncode}")
    finally:
        if temp_name:
            Path(temp_name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--dsn-file", required=True)
    create.add_argument("--key-file", required=True)
    create.add_argument("--output", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--key-file", required=True)
    verify.add_argument("--backup", required=True)
    args = parser.parse_args(argv)
    if args.command == "create":
        dsn = Path(args.dsn_file).read_text(encoding="utf-8").strip()
        create_backup(dsn, args.output, args.key_file)
    else:
        verify_backup(args.backup, args.key_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
