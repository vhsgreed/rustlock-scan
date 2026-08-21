#!/usr/bin/env python3
"""rustlock-scan — flag known-malicious crate versions in Cargo.lock files.

Tracks the 2026-08-20 Rust supply-chain incident (compromised `droundy`
account + `proc-macro1` typosquat), which shipped malicious build scripts
via arrayref 0.3.10, internment 0.8.7, append-only-vec 0.1.9 and a set of
removed dependency crates (proc-macro1, proc-macro-en, arone, aronenao,
tinymember, aovine).

Data source: rustsec/advisory-db RUSTSEC-2026-0259..0266
  https://github.com/rustsec/advisory-db/tree/main/crates
  https://safedep.io/arrayref-proc-macro1-rust-build-time-malware/

Stdlib only (tomllib, Python 3.11+). Local, offline, no network calls.

Usage:
    python3 scan.py [path/to/Cargo.lock ...]
    (defaults to ./Cargo.lock if no paths given)

Exit status: 1 if any compromised version is found, 0 otherwise.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

# name -> (bad_versions or None=any, safe_pin)
# bad_versions: exact versions that are compromised; None means every
# published version of the crate is malicious (crate fully removed).
KNOWN = {
    "arrayref": ({"0.3.10"}, "0.3.9"),
    "internment": ({"0.8.7"}, "0.8.6"),
    "append-only-vec": ({"0.1.9"}, "0.1.8"),
    "proc-macro1": (None, None),
    "proc-macro-en": (None, None),
    "arone": (None, None),
    "aronenao": (None, None),
    "tinymember": (None, None),
    "aovine": (None, None),
}


def scan_lockfile(path: Path) -> list[tuple[str, str]]:
    """Return [(name, version), ...] of compromised packages in a Cargo.lock."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"  ! {path}: cannot parse ({exc.__class__.__name__})", file=sys.stderr)
        return []

    hits: list[tuple[str, str]] = []
    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name in KNOWN:
            bad_versions, _ = KNOWN[name]
            if bad_versions is None or version in bad_versions:
                hits.append((name, version))
    return hits


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] or [Path("Cargo.lock")]
    found_any = False

    for path in paths:
        hits = scan_lockfile(path)
        if not hits:
            print(f"OK  {path}: no known compromised crates")
            continue
        found_any = True
        print(f"HIT {path}: {len(hits)} compromised package(s)")
        for name, version in hits:
            bad_versions, pin = KNOWN[name]
            hint = f" -> cargo update -p {name} --precise {pin}" if pin else " -> remove the dependency (crate fully removed from crates.io)"
            print(f"    - {name} {version}{hint}")

    if found_any:
        print("\nRemediation: run the suggested `cargo update` commands, then")
        print("`cargo audit` (rustsec advisory-db already covers all of these).")
        print("The payloads also drop /tmp/rust-setup (Unix) or %TEMP%\\rust-setup*")
        print("(Windows); check for those files and scan for 23.254.165.112 traffic.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
