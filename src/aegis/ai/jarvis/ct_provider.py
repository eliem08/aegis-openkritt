"""Concrete passive CT provider and durable record serialization."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from hashlib import sha256
from urllib.parse import quote

from .recon_intelligence import CertificateRecord

_DOMAIN = re.compile(r"^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.I)


class CTProviderError(RuntimeError):
    pass


def _time(value: str) -> datetime:
    rendered = str(value or "").strip().replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CTProviderError(f"invalid CT timestamp: {value}") from exc
    return parsed.replace(tzinfo=parsed.tzinfo or UTC).astimezone(UTC)


def serialize_record(record: CertificateRecord) -> dict:
    return {
        "fingerprint": record.fingerprint, "sans": list(record.sans),
        "issuer": record.issuer, "subject": record.subject, "serial": record.serial,
        "not_before": record.not_before.isoformat(), "not_after": record.not_after.isoformat(),
        "observed_at": record.observed_at.isoformat(), "source": record.source,
    }


def deserialize_record(row: dict) -> CertificateRecord:
    return CertificateRecord(
        str(row["fingerprint"]), tuple(row.get("sans") or ()), str(row.get("issuer") or ""),
        str(row.get("subject") or ""), str(row.get("serial") or ""),
        _time(row["not_before"]), _time(row["not_after"]), _time(row["observed_at"]),
        str(row.get("source") or "certificate_transparency"),
    )


class CrtShProvider:
    """Query crt.sh through an injected passive-provider scoped fetch boundary."""

    provider_host = "crt.sh"

    def __init__(self, fetcher, *, max_response_bytes: int = 5_000_000) -> None:
        self.fetcher = fetcher
        self.max_response_bytes = max_response_bytes

    def query(self, domain: str) -> tuple[CertificateRecord, ...]:
        normalized = domain.casefold().strip().rstrip(".")
        if not _DOMAIN.fullmatch(normalized):
            raise CTProviderError("invalid CT domain")
        url = f"https://crt.sh/?q={quote('%.' + normalized.lstrip('*.'))}&output=json"
        try:
            status, _headers, body = self.fetcher.get(url)
        except Exception as exc:
            raise CTProviderError(f"CT provider request failed: {type(exc).__name__}") from exc
        if status != 200:
            raise CTProviderError(f"CT provider returned HTTP {status}")
        if len(body) > self.max_response_bytes:
            raise CTProviderError("CT provider response exceeded size budget")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CTProviderError("CT provider returned invalid JSON") from exc
        if not isinstance(payload, list):
            raise CTProviderError("CT provider response is not a record list")
        now = datetime.now(UTC)
        records: dict[str, CertificateRecord] = {}
        for row in payload:
            if not isinstance(row, dict):
                continue
            sans = tuple(sorted({
                item.casefold().strip().rstrip(".")
                for item in str(row.get("name_value") or "").splitlines()
                if item.strip()
            }))
            if not sans:
                continue
            serial = str(row.get("serial_number") or row.get("id") or "")
            material = "\x1f".join((serial, *sans, str(row.get("issuer_name") or "")))
            fingerprint = sha256(material.encode()).hexdigest()
            try:
                record = CertificateRecord(
                    fingerprint, sans, str(row.get("issuer_name") or ""),
                    str(row.get("common_name") or ""), serial,
                    _time(row.get("not_before") or row.get("entry_timestamp")),
                    _time(row.get("not_after") or row.get("entry_timestamp")),
                    now, "crt.sh",
                )
            except CTProviderError:
                continue
            records[fingerprint] = record
        return tuple(sorted(records.values(), key=lambda item: item.fingerprint))


__all__ = [
    "CTProviderError", "CrtShProvider", "deserialize_record", "serialize_record",
]
