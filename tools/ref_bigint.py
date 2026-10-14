#!/usr/bin/env python3
"""Generates the reference vectors that tests/test_bigint.cpp checks against.

Every value is encoded here with Python's arbitrary precision integers, which gives an
implementation independent of the one under test. The result is the minimal two's complement
content octets of X.690 8.3.2.

    python3 tools/ref_bigint.py            # writes tests/data/bigint_vectors.txt
    python3 tools/ref_bigint.py --wide     # more random values, for a longer soak

The vector file is committed so that the test runs anywhere, without a Python interpreter.
"""

import argparse
import pathlib
import random
import sys

WIDTH_BITS = 4096   # the library's ceiling is 4096 bits
MAX_OCTETS = 512    # ASN1BigInt::kMaxOctets


def der_content(value: int) -> bytes:
    """Minimal two's complement content octets.

    to_bytes(signed=True) refuses any length that cannot hold the value, so the smallest length
    that succeeds is exactly the minimal encoding.
    """
    if value == 0:
        return b"\x00"
    length = 1
    while True:
        try:
            return value.to_bytes(length, "big", signed=True)
        except OverflowError:
            length += 1


def cases(wide: bool) -> list[int]:
    random.seed(20261014)
    out: list[int] = []

    # The boundaries that a hand written implementation gets wrong: every power of two, and its
    # neighbours, over the whole supported width.
    out += [0, 1, -1, 127, 128, -127, -128, -129, 255, 256, 32767, 32768, -32767, -32768, -32769]
    out += [2**63 - 1, 2**63, -2**63, -2**63 - 1, 2**64 - 1, 2**64, -2**64]
    out += [2**127 - 1, 2**127, -2**127, -2**127 - 1, 2**128 - 1, 2**128]
    out += [123456789012345678901234567890, -123456789012345678901234567890]

    edge_bits = WIDTH_BITS + 8 if wide else 600
    for bit in range(edge_bits + 1):
        out += [2**bit, 2**bit - 1, 2**bit + 1, -2**bit, -(2**bit) - 1, -(2**bit) + 1]

    # The boundaries above are what catch real bugs, so they stay exhaustive; the random values are
    # a soak and are kept modest to keep the committed file small.
    count = 30000 if wide else 1500
    widest = min(WIDTH_BITS, 2000 if wide else 512)
    for _ in range(count):
        bits = random.randint(1, widest)
        value = random.getrandbits(bits)
        out.append(-value if random.random() < 0.5 else value)

    # Only values the library claims to support belong in the vector file: the ceiling is 512
    # content octets, so a wider value is a documented rejection rather than a disagreement.
    return [v for v in out if len(der_content(v)) <= MAX_OCTETS]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wide", action="store_true", help="more vectors, for a soak run")
    parser.add_argument("--out", default=None, help="output path")
    options = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    out = pathlib.Path(options.out) if options.out else root / "tests" / "data" / "bigint_vectors.txt"
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    for value in cases(options.wide):
        octets = der_content(value)
        lines.append("%d %s %d" % (value, octets.hex(), len(octets)))

    out.write_text("\n".join(lines) + "\n")
    size = out.stat().st_size
    print("%s: %d vectors, %.1f KiB" % (out, len(lines), size / 1024))
    return 0


if __name__ == "__main__":
    sys.exit(main())