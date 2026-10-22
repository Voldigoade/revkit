#!/usr/bin/env python3
"""Reject the forbidden em dash in tracked text files."""

import subprocess
import sys
from pathlib import Path


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files", "-z"], check=True, stdout=subprocess.PIPE
    )
    failures = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        path = Path(raw_path.decode("utf-8", "surrogateescape"))
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            continue
        except OSError as error:
            print(f"cannot read {path}: {error}", file=sys.stderr)
            return 2
        if b"\0" not in data and "\u2014".encode() in data:
            failures.append(str(path))
    if failures:
        print("U+2014 is forbidden in tracked text files:", *failures, sep="\n", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
