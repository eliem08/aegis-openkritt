"""Binary/template pinning tool (Phase 5 §Isolation and supply chain).

Turns a *downloaded, provenance-checked* release into a recorded digest. This is
the mechanism the operator runs where the binaries and legal clearance exist — it
does NOT fetch anything itself and never invents a digest. Workflow:

1. Download the exact release and its publisher checksum/signature out of band.
2. ``pin_from_file(path, tool=..., version=..., expected_sha256=<publisher value>)``
   computes the file's SHA-256 and **fails closed on any mismatch** — so a
   tampered download is refused, not pinned.
3. ``save_pins`` writes ``pins.json``. The platform loads it at startup and the
   adapters verify the on-disk binary against the pinned digest before running.

The package itself ships with empty digests, so an unpinned deployment fails
closed; pinning is an explicit, auditable, operator-run step.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


class PinError(RuntimeError):
    pass


class PinMismatch(PinError):
    """The computed digest does not match the publisher-declared value."""


@dataclass(frozen=True)
class PinnedTool:
    tool: str
    version: str
    sha256: str
    source: str = ""          # release URL / provenance
    signed_by: str = ""       # publisher signing identity, if verified
    pinned_at: str = ""


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def pin_from_file(path: str, *, tool: str, version: str, expected_sha256: str | None = None,
                  source: str = "", signed_by: str = "") -> PinnedTool:
    """Pin a downloaded release file; fail closed if it doesn't match ``expected``."""
    computed = digest_file(path)
    if expected_sha256 and computed.lower() != expected_sha256.strip().lower():
        raise PinMismatch(
            f"{tool} {version}: computed {computed} != publisher {expected_sha256} "
            "(tampered/corrupt download — refusing to pin)")
    return PinnedTool(tool=tool, version=version, sha256=computed, source=source,
                      signed_by=signed_by, pinned_at=datetime.now(UTC).isoformat())


def save_pins(pins, path: str = "pins.json") -> None:
    data = {p.tool: asdict(p) for p in pins}
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def load_pins(path: str = "pins.json") -> dict[str, PinnedTool]:
    if not Path(path).exists():
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {tool: PinnedTool(**entry) for tool, entry in raw.items()}


def digest_for(tool: str, pins: dict[str, PinnedTool]) -> str | None:
    entry = pins.get(tool)
    return entry.sha256 if entry else None


def verify_against_pin(path: str, tool: str, pins: dict[str, PinnedTool]) -> bool:
    """True iff the on-disk file matches the pinned digest. Fail closed if unpinned."""
    expected = digest_for(tool, pins)
    if not expected:
        raise PinError(f"{tool!r} is not pinned")
    return digest_file(path) == expected


def _main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Pin a downloaded release into pins.json")
    parser.add_argument("path")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--expected", help="publisher-declared sha256 (fails closed on mismatch)")
    parser.add_argument("--source", default="")
    parser.add_argument("--pins", default="pins.json")
    args = parser.parse_args(argv)

    pins = load_pins(args.pins)
    pinned = pin_from_file(args.path, tool=args.tool, version=args.version,
                           expected_sha256=args.expected, source=args.source)
    merged = list(pins.values()) + [pinned]
    save_pins({p.tool: p for p in merged}.values(), args.pins)
    print(f"pinned {pinned.tool} {pinned.version} sha256={pinned.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
