#!/usr/bin/env python3
"""Small deterministic CLI boundary around the third-party pefile parser."""

from __future__ import annotations

import json
import sys

import pefile


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] in {"--version", "version", "-version"}:
        print(f"pefile {pefile.__version__}")
        return 0
    if len(sys.argv) != 2:
        print("usage: pefile <portable-executable>", file=sys.stderr)
        return 2
    image = pefile.PE(sys.argv[1], fast_load=False)
    characteristics = int(image.OPTIONAL_HEADER.DllCharacteristics)
    print(json.dumps({
        "machine": int(image.FILE_HEADER.Machine),
        "dll_characteristics": characteristics,
        "nx_compat": bool(characteristics & 0x0100),
        "sections": [
            section.Name.rstrip(b"\x00").decode("ascii", "replace")
            for section in image.sections
        ],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
