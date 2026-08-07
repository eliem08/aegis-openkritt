"""Generate local production secrets without printing secret material."""

from __future__ import annotations

import argparse
import json
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class BootstrapRefused(RuntimeError):
    pass


def _write(path: Path, value: str | bytes, *, force: bool) -> None:
    if path.exists() and not force:
        raise BootstrapRefused(f"refusing to overwrite existing secret file: {path.name}")
    data = value.encode("utf-8") if isinstance(value, str) else value
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _certificate_pair(hostname: str):
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis local production CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=False, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=397))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        ca_cert.public_bytes(serialization.Encoding.PEM),
        server_cert.public_bytes(serialization.Encoding.PEM),
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def bootstrap(output: str | Path = "secrets", *, force: bool = False) -> list[Path]:
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass

    postgres_password = secrets.token_urlsafe(36)
    redis_password = secrets.token_urlsafe(36)
    api_token = secrets.token_urlsafe(40)
    signing_secret = secrets.token_urlsafe(48)
    egress_secret = secrets.token_urlsafe(48)

    values: dict[str, str | bytes] = {
        "postgres_password": postgres_password,
        "redis_password": redis_password,
        "api_keys.json": json.dumps({
            api_token: {"role": "operator", "tenant": "tenant-primary", "name": "bootstrap-operator"},
        }, separators=(",", ":")),
        "signing_keys.json": json.dumps({"bootstrap-hmac-v1": signing_secret}, separators=(",", ":")),
        "encryption_key": Fernet.generate_key(),
        "backup_encryption_key": Fernet.generate_key(),
        "egress_signing_key": egress_secret,
        "database_url": (
            "postgresql://svc_aegis:"
            + quote(postgres_password, safe="")
            + "@pg.prod.internal:5432/aegis?sslmode=verify-full&sslrootcert=/run/secrets/postgres_ca"
        ),
        "redis_url": (
            "redis://default:"
            + quote(redis_password, safe="")
            + "@redis.prod.internal:6379/0"
        ),
        "scanner-releases.lock.json": json.dumps({"schema": 1, "releases": []}, indent=2),
    }
    ca, cert, key = _certificate_pair("pg.prod.internal")
    values.update({
        "postgres_ca.pem": ca,
        "postgres_server_cert.pem": cert,
        "postgres_server_key.pem": key,
    })
    paths: list[Path] = []
    for name, value in values.items():
        path = root / name
        _write(path, value, force=force)
        paths.append(path)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="secrets")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    paths = bootstrap(args.output, force=args.force)
    print(f"created {len(paths)} secret/config files under {Path(args.output).resolve()}")
    print("secret values were not printed; store the directory securely")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
