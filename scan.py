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
    python3 scan.py [--strict] [path/to/Cargo.lock ...]
    (defaults to ./Cargo.lock if no paths given)

Exit status:
    1 if any compromised version is found, or if --strict is given and any
    typosquat warning is emitted; 0 otherwise.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from typosquat import flagged_names

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

# High-value crates commonly targeted by typosquatting.
POPULAR = {
    "serde", "tokio", "reqwest", "axum", "clap", "thiserror", "rand",
    "anyhow", "rayon", "log", "futures", "hyper", "tracing", "sqlx",
    "syn", "quote", "proc-macro2", "once_cell", "lazy_static", "regex",
    "chrono", "uuid", "serde_json", "actix-web", "tonic",
}


def scan_lockfile(path: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    """Return (hits, typos) for a Cargo.lock file.

    hits: [(name, version)] of known compromised packages.
    typos: [(name, version, similar_popular)] where name is within edit
           distance <=2 of a popular crate and not itself popular/known.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"  ! {path}: cannot parse ({exc.__class__.__name__})", file=sys.stderr)
        return [], []

    hits: list[tuple[str, str]] = []
    typos: list[tuple[str, str, str]] = []

    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")

        # Known compromised check
        if name in KNOWN:
            bad_versions, _ = KNOWN[name]
            if bad_versions is None or version in bad_versions:
                hits.append((name, version))
            continue  # skip typo check for known crates

        # Typosquat check via the scoring engine (typosquat.py).
        # flagged_names returns [(score, reason, popular)] above threshold.
        for score, reason, popular in flagged_names(name):
            typos.append((name, version, f"{popular} ({reason}, score {score})"))

    return hits, typos


def main(argv: list[str]) -> int:
    # Parse --strict flag
    strict = False
    args = []
    for arg in argv:
        if arg == "--strict":
            strict = True
        else:
            args.append(arg)

    paths = [Path(a) for a in args] or [Path("Cargo.lock")]
    found_hits = False
    found_typos = False

    for path in paths:
        hits, typos = scan_lockfile(path)
        if not hits and not typos:
            print(f"OK  {path}: no known compromised crates, no typosquat warnings")
            continue

        if hits:
            found_hits = True
            print(f"HIT {path}: {len(hits)} compromised package(s)")
            for name, version in hits:
                bad_versions, pin = KNOWN[name]
                hint = f" -> cargo update -p {name} --precise {pin}" if pin else " -> remove the dependency (crate fully removed from crates.io)"
                print(f"    - {name} {version}{hint}")

        if typos:
            found_typos = True
            print(f"TYPO? {path}: {len(typos)} potential typosquat(s)")
            for name, version, similar in typos:
                print(f"    - {name} {version} (similar to {similar})")

    if found_hits:
        print("\nRemediation: run the suggested `cargo update` commands, then")
        print("`cargo audit` (rustsec advisory-db already covers all of these).")
        print("The payloads also drop /tmp/rust-setup (Unix) or %TEMP%\\rust-setup*")
        print("(Windows); check for those files and scan for 23.254.165.112 traffic.")
        return 1

    if strict and found_typos:
        print("\n--strict: typosquat warnings treated as errors.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
