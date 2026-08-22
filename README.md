# rustlock-scan

Offline-first Cargo.lock security scanner for the 2026-08-20 Rust supply-chain
incident, plus an online advisory cross-reference. Stdlib only (Python 3.11+,
`tomllib`); no third-party dependencies.

## scan.py — malicious-crate scan (offline)

Flags the known typosquat/compromised crates from the 2026-08-20 `droundy`
incident (RUSTSEC-2026-0259..0266): `arrayref 0.3.10`, `internment 0.8.7`,
`append-only-vec 0.1.9`, and the fully-removed crates (`proc-macro1`,
`proc-macro-en`, `arone`, `aronenao`, `tinymember`, `aovine`).

```sh
python3 scan.py [path/to/Cargo.lock ...]   # defaults to ./Cargo.lock
```

Exit 1 if any compromised version is found. No network needed.

## advisories.py — vulnerability scan (online, cacheable)

Cross-references every crate in a Cargo.lock against the OSV API
(`ecosystem=crates.io`) and reports known RUSTSEC/GHSA advisories affecting
the locked versions, with a `cargo update -p <crate> --precise <fixed>` hint.

```sh
python3 advisories.py [Cargo.lock ...] [--db cache.json] [--offline]
```

- Results are cached in `--db` (default `./advisories-cache.json`), so
  re-runs are offline once warmed.
- `--offline` never touches the network; crates without a cache entry are
  reported as unchecked.
- Exit 1 if any vulnerable version is found; 0 otherwise.

Example (h2 RUSTSEC-2026-0258, fixed in 0.4.16):

```
HIT Cargo.lock: 1 vulnerable package(s)
    - h2 0.4.15  RUSTSEC-2026-0258 (LOW)  h2 unbounded empty DATA frames
        -> cargo update -p h2 --precise 0.4.16
```

## Tests

```sh
python3 -m unittest test_advisories -v
```

## Usage in CI / cron

```sh
python3 scan.py Cargo.lock || echo "malware hit"
python3 advisories.py Cargo.lock --db /var/cache/rustlock.json || echo "vulns found"
```
