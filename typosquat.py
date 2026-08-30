#!/usr/bin/env python3
"""typosquat.py — scoring engine for crate-name typosquat detection.

Distinguishes real typosquat patterns (digit-suffix clones, edit-distance
near-misses, separator variants) from legitimate ecosystem derivatives
(tokio-util, serde_derive, axum-core). Explainable: every hit carries a
reason and a score, so it is auditable instead of a black box.

Design goals:
  - Offline-first, stdlib only (Python 3.11+), no network calls.
  - Deterministic and testable via pure functions (see test_typosquat.py).
  - Low false positives: known derivatives are allowlisted and suppressed;
    weak signals (bare prefix matches) stay below the report threshold.

Usage:
    from typosquat import score_name, REPORT_THRESHOLD

    hits = score_name("proc-macro1")   # -> [(4, "digit-suffix of proc-macro2"), ...]
"""

from __future__ import annotations

# High-value crates commonly targeted by typosquatting.
POPULAR = {
    "serde", "tokio", "reqwest", "axum", "clap", "thiserror", "rand",
    "anyhow", "rayon", "log", "futures", "hyper", "tracing", "sqlx",
    "syn", "quote", "proc-macro2", "once_cell", "lazy_static", "regex",
    "chrono", "uuid", "serde_json", "actix-web", "tonic",
}

# Legitimate ecosystem derivatives of POPULAR crates. A crate whose name
# matches one of these exactly is NOT a typosquat, even if it is a prefix
# variant of a popular crate. Keep this list current; it is the false
# positive shield.
DERIVATIVES = {
    "tokio-util", "tokio-stream", "tokio-rustls", "tokio-tungstenite",
    "tokio-openssl", "tokio-native-tls", "tokio-macros", "tokio-test",
    "serde_derive", "serde_yaml", "serde_json", "serde_cbor", "serde-xml-rs",
    "serde_urlencoded", "serde_plain", "serde_repr", "serde_with",
    "serde_spanned", "serde_ignored", "serde_stacker",
    "axum-core", "axum-extra", "axum-macros", "axum-server",
    "reqwest-middleware", "reqwest-retry", "reqwest-eventsource",
    "hyper-util", "hyper-tls", "hyper-rustls", "hyper-timeout",
    "hyper-proxy", "hyper-openssl",
    "sqlx-core", "sqlx-macros", "sqlx-postgres", "sqlx-mysql", "sqlx-sqlite",
    "tracing-subscriber", "tracing-core", "tracing-appender",
    "tracing-opentelemetry", "tracing-log", "tracing-futures",
    "proc-macro-error", "proc-macro-hack", "proc-macro-crate",
    "syn_derive", "synstructure", "syn-mid", "quote-spanned",
    "actix-rt", "actix-web-actors", "actix-http", "actix-files",
    "rand_chacha", "rand_core", "rand_pcg", "rand_distr",
    "futures-util", "futures-executor", "futures-channel", "futures-core",
    "futures-io", "futures-macro", "futures-task", "futures-sink",
    "chrono-tz", "regex-automata", "regex-syntax",
    "once_cell_derive", "lazy_static_derive", "uuid-mt", "uuid-b64",
}

# Report any name whose best score meets or exceeds this.
REPORT_THRESHOLD = 2


def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,            # deletion
                curr[j - 1] + 1,        # insertion
                prev[j - 1] + (ca != cb)  # substitution
            ))
        prev = curr
    return prev[-1]


def _separator_variants(name: str) -> set[str]:
    """Normalize separator characters so 'serde-json' and 'serde_json'
    compare equal; also drop separators entirely for near-miss checks."""
    return {
        name.replace("-", "_"),
        name.replace("_", "-"),
        name.replace("-", "").replace("_", ""),
    }


def _digit_suffix_match(name: str, popular: str) -> bool:
    """True when name == popular + trailing digits, e.g. 'serde1',
    'tokio3', or when name reuses the stem of a digit-suffixed popular
    crate with a different trailing digit, e.g. 'proc-macro1' vs
    'proc-macro2'."""
    # Case 1: name == popular + digits (same length-extension)
    if len(name) > len(popular):
        stem, suffix = name[: len(popular)], name[len(popular):]
        if stem == popular and suffix.isdigit():
            return True
    # Case 2: popular ends in a digit: compare stems, require a
    # different trailing digit. Same length is allowed (proc-macro1
    # vs proc-macro2).
    if popular[-1].isdigit() and name[-1].isdigit():
        pop_stem, pop_digit = popular[:-1], popular[-1]
        if len(name) == len(popular) and name.startswith(pop_stem) \
                and name[-1:] != pop_digit:
            return True
    return False


def score_name(name: str) -> list[tuple[int, str, str]]:
    """Score a crate name against POPULAR. Returns a list of
    (score, reason, similar_popular) for every signal found, sorted by
    score descending. Scores below REPORT_THRESHOLD are included so
    callers may choose their own threshold, but flagged_names() filters.

    Rules (additive per popular crate, best reason kept per crate):
      - exact name == popular: omitted (caller should skip known crates)
      - separator variant of popular           -> 2  (serde-json / serde_json)
      - digit-suffix of popular                -> 4  (serde1, proc-macro1)
      - levenshtein distance 1                 -> 3
      - levenshtein distance 2                 -> 2
      - prefix of popular with extra suffix    -> 1  (weak; below threshold
                                            unless a stronger rule also fires)
    A name matching DERIVATIVES exactly is suppressed entirely (it is a
    legitimate ecosystem crate).
    """
    if name in DERIVATIVES:
        return []

    results: list[tuple[int, str, str]] = []
    variants = _separator_variants(name)

    for popular in POPULAR:
        if name == popular:
            continue

        # Separator variant: serde-json <-> serde_json, same crate family.
        if popular in variants or name in _separator_variants(popular):
            results.append((2, f"separator variant of {popular}", popular))
            continue

        # Digit-suffix clone: proc-macro1, serde2, tokio3. The classic
        # version-confusion typosquat and the exact pattern used in the
        # 2026-08-20 incident (proc-macro1, proc-macro-en).
        if _digit_suffix_match(name, popular):
            results.append((4, f"digit-suffix clone of {popular}", popular))
            continue

        # Edit distance: near-miss of a popular crate name.
        dist = levenshtein(name.lower(), popular.lower())
        if dist == 1:
            results.append((3, f"edit distance 1 from {popular}", popular))
        elif dist == 2:
            results.append((2, f"edit distance 2 from {popular}", popular))

        # Weak prefix signal: popular name as a prefix with extra suffix,
        # e.g. 'tokio-whatever'. Usually a legit family crate; score 1 so
        # it stays below the default threshold but is visible in --json.
        if len(name) > len(popular) and name.startswith(popular):
            results.append((1, f"prefix of {popular}", popular))

    # Deduplicate by (score, similar) keeping the best reason, then sort.
    seen: set[tuple[int, str]] = set()
    deduped: list[tuple[int, str, str]] = []
    for score, reason, similar in sorted(results, key=lambda r: -r[0]):
        key = (score, similar)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((score, reason, similar))
    return deduped


def flagged_names(name: str, threshold: int = REPORT_THRESHOLD) -> list[tuple[int, str, str]]:
    """Return only signals at or above `threshold` (default 2)."""
    return [(s, r, p) for s, r, p in score_name(name) if s >= threshold]


if __name__ == "__main__":
    import sys

    for candidate in sys.argv[1:]:
        hits = flagged_names(candidate)
        if hits:
            for score, reason, similar in hits:
                print(f"TYPO? {candidate}: score {score} ({reason})")
        else:
            print(f"OK    {candidate}: no typosquat signal")