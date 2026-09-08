#!/usr/bin/env python3
"""Convert between TIP-899's raw ML-DSA-44 public key and OpenSSL SPKI DER."""

from pathlib import Path
import sys


# SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.3.17 }, BIT STRING <1312-byte key> }
SPKI_PREFIX = bytes.fromhex("30820532300b06096086480165030403110382052100")
RAW_PUBLIC_KEY_LENGTH = 1312


def extract(source: Path, destination: Path) -> None:
    encoded = source.read_bytes()
    expected_length = len(SPKI_PREFIX) + RAW_PUBLIC_KEY_LENGTH
    if len(encoded) != expected_length or not encoded.startswith(SPKI_PREFIX):
        raise SystemExit(
            f"unexpected ML-DSA-44 SPKI encoding: length={len(encoded)}, "
            f"expected={expected_length}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded[len(SPKI_PREFIX) :])


def wrap(source: Path, destination: Path) -> None:
    raw = source.read_bytes()
    if len(raw) != RAW_PUBLIC_KEY_LENGTH:
        raise SystemExit(
            f"ML-DSA-44 raw public key must be {RAW_PUBLIC_KEY_LENGTH} bytes, "
            f"got {len(raw)}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(SPKI_PREFIX + raw)


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in {"extract", "wrap"}:
        raise SystemExit(
            "usage: ml_dsa_spki.py extract <public.der> <public-key.bin>\n"
            "       ml_dsa_spki.py wrap <public-key.bin> <public.der>"
        )
    command, source, destination = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    if command == "extract":
        extract(source, destination)
    else:
        wrap(source, destination)


if __name__ == "__main__":
    main()
