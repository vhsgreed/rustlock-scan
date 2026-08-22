#!/usr/bin/env python3
"""rustlock-scan advisories — cross-reference Cargo.lock against known
security advisories (RUSTSEC/GHSA) via the OSV API.

Companion to scan.py (offline typosquat/malware scan). This one checks for
*known vulnerabilities* in locked versions, e.g.:

    RUSTSEC-2026-0258 (h2 <= 0.4.15, unbounded empty DATA frames -> OOM/panic)

Stdlib only (tomllib, urllib, json, Python 3.11+). Network is optional:
results are cached in a JSON db file so re-runs can be fully offline.

Usage:
    python3 advisories.py [Cargo.lock ...] [--db cache.json] [--offline]
    (defaults to ./Cargo.lock, cache ./advisories-cache.json, online)

Exit status: 1 if any vulnerable version found, 0 otherwise. Unchecked
crates (offline + no cache) are reported as warnings, not failures.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
import urllib.request
from pathlib import Path

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
ECOSYSTEM = "crates.io"


# ---------------------------------------------------------------- versions

def parse_version(v: str) -> tuple:
    """Parse a semver-ish string into a comparable tuple.

    Handles '0.4.16', '1.2', '1', prereleases ('1.0.0-alpha.1' < '1.0.0')
    and OSV's bare '0' / '0.0.0-0' introduced markers. A release with no
    prerelease compares greater than any prerelease of the same core
    (semver rule); numeric prerelease segments sort before alphanumeric.
    """
    core, _, pre = v.partition("-")
    parts = []
    for bit in core.split("."):
        try:
            parts.append(int(bit))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    if not pre:
        prekey = (1,)  # release > any prerelease
    else:
        segs = []
        for p in pre.split("."):
            try:
                segs.append((0, int(p)))      # numeric segment
            except ValueError:
                segs.append((1, p.lower()))   # alphanumeric segment
        prekey = (0,) + tuple(segs)
    return tuple(parts[:3]), prekey


def _in_range(version: tuple, events: list[dict]) -> bool:
    """Test a parsed version against one OSV range's event list.

    Events are walked in order; a range is a sequential band:
    [introduced, fixed) or [introduced, last_affected].
    """
    introduced = parse_version("0")
    upper_excl: tuple | None = None
    upper_incl: tuple | None = None
    for ev in events:
        if "introduced" in ev:
            introduced = parse_version(str(ev["introduced"]))
        elif "fixed" in ev:
            upper_excl = parse_version(str(ev["fixed"]))
        elif "last_affected" in ev:
            upper_incl = parse_version(str(ev["last_affected"]))
    if version < introduced:
        return False
    if upper_excl is not None and version >= upper_excl:
        return False
    if upper_incl is not None and version > upper_incl:
        return False
    return True


def version_is_affected(version: str, affected: list[dict]) -> bool:
    """True if `version` falls inside any affected entry of an OSV vuln."""
    parsed = parse_version(version)
    for entry in affected:
        if entry.get("package", {}).get("ecosystem") != ECOSYSTEM:
            continue
        ranges = entry.get("ranges")
        if ranges:
            for r in ranges:
                if _in_range(parsed, r.get("events", [])):
                    return True
            continue
        explicit = entry.get("versions")
        if explicit:
            if version in explicit:
                return True
            continue
        # No ranges and no explicit list: treat as affecting all versions.
        return True
    return False


def fixed_version(affected: list[dict]) -> str | None:
    """Best 'fixed' version across affected entries (max of the minima)."""
    fixes: list[tuple] = []
    for entry in affected:
        for r in entry.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    raw = str(ev["fixed"])
                    fixes.append((parse_version(raw), raw))
    return max(fixes)[1] if fixes else None


# ------------------------------------------------------------------- OSV

def query_osv(name: str, timeout: int = 20) -> dict:
    """Ask OSV for all advisories touching a crates.io package."""
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=json.dumps({"package": {"ecosystem": ECOSYSTEM, "name": name}}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "rustlock-scan/0.2"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def load_cache(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            print(f"  ! {path}: unreadable cache, starting fresh", file=sys.stderr)
    return {}


def save_cache(path: Path, cache: dict) -> None:
    path.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")


# ------------------------------------------------------------------- scan

def crates_in_lockfile(path: Path) -> dict[str, str]:
    """name -> version for every package in a Cargo.lock."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"  ! {path}: cannot parse ({exc.__class__.__name__})", file=sys.stderr)
        return {}
    return {p.get("name", ""): p.get("version", "") for p in data.get("package", [])
            if p.get("name") and p.get("version")}


def severity(vuln: dict) -> str:
    ds = vuln.get("database_specific") or {}
    sev = ds.get("severity")
    if sev:
        return str(sev)
    # Some RustSec entries carry the severity in aliases' GHSA metadata; fall
    # back to a neutral marker when absent.
    return "n/a"


def summarize(vuln: dict) -> str:
    return (vuln.get("summary") or vuln.get("details") or "")[:110].strip()


def check_lockfile(path: Path, cache: dict, offline: bool) -> tuple[list, list]:
    """Return (hits, unchecked) for one lockfile. Hits are tuples of
    (name, version, vuln_id, sev, summary, fixed)."""
    crates = crates_in_lockfile(path)
    hits: list[tuple] = []
    unchecked: list[str] = []

    for name, version in sorted(crates.items()):
        if name in cache:
            result = cache[name]
        elif offline:
            unchecked.append(f"{name} {version} (offline, no cache entry)")
            continue
        else:
            try:
                result = query_osv(name)
            except Exception as exc:  # network hiccup, timeout, bad JSON
                unchecked.append(f"{name} {version} (query failed: {exc.__class__.__name__})")
                continue
            cache[name] = result
            # Keep the agent's machine calm on big lockfiles.
            if len(crates) > 1:
                import time
                time.sleep(0.25)

        for vuln in result.get("vulns", []):
            affected = vuln.get("affected", [])
            if version_is_affected(version, affected):
                fixed = fixed_version(affected)
                hits.append((name, version,
                             vuln.get("id", "?"),
                             severity(vuln),
                             summarize(vuln),
                             fixed))

    return hits, unchecked


# ------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Advisory scan for Cargo.lock (OSV)")
    ap.add_argument("paths", nargs="*", type=Path, default=[Path("Cargo.lock")],
                    help="Cargo.lock files (default: ./Cargo.lock)")
    ap.add_argument("--db", type=Path, default=Path("advisories-cache.json"),
                    help="JSON cache file (default: ./advisories-cache.json)")
    ap.add_argument("--offline", action="store_true",
                    help="never query the network; use cache only")
    args = ap.parse_args(argv)

    cache = load_cache(args.db)
    found_any = False

    for path in args.paths:
        hits, unchecked = check_lockfile(path, cache, args.offline)
        if not hits:
            status = "OK "
            if unchecked:
                status = "?? "
            print(f"{status} {path}: no known vulnerable crates"
                  + (f" ({len(unchecked)} unchecked)" if unchecked else ""))
        else:
            found_any = True
            print(f"HIT {path}: {len(hits)} vulnerable package(s)")
            for name, version, vid, sev, summary, fixed in hits:
                hint = (f"cargo update -p {name} --precise {fixed}"
                        if fixed else "cargo update -p {name}")
                print(f"    - {name} {version}  {vid} ({sev})  {summary}")
                print(f"        -> {hint}")

        for item in unchecked:
            print(f"  ! {path}: unchecked: {item}", file=sys.stderr)

    save_cache(args.db, cache)

    if found_any:
        print("\nRemediation: run the suggested `cargo update` commands, then")
        print("`cargo audit` for the full advisory picture. Re-run this scan")
        print("after updating to confirm.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
