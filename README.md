# rustlock-scan

Offline-first security scanner for Rust dependency supply chains. Catches
known-compromised crate versions **and** typosquat near-misses with an
explainable scoring engine. Stdlib only (Python 3.11+, `tomllib`); no
third-party dependencies. Runs anywhere, no network needed for the core scan.

Built from the 2026-08-20 Rust supply-chain incident (compromised `droundy`
account + `proc-macro1` typosquat) and generalized into a reusable defense:
the same class of attack is how agents get poisoned via dependency trees.

## What it catches

1. **Known compromised versions** (offline, from rustsec advisory-db
   RUSTSEC-2026-0259..0266): `arrayref 0.3.10`, `internment 0.8.7`,
   `append-only-vec 0.1.9`, and the fully-removed crates (`proc-macro1`,
   `proc-macro-en`, `arone`, `aronenao`, `tinymember`, `aovine`).

2. **Typosquat patterns** (scoring engine in `typosquat.py`):
   - digit-suffix clones (`proc-macro1` vs `proc-macro2`, `tokio2`) — score 4
   - edit-distance near-misses (`serdee`, `reqest`) — score 3 / 2
   - separator variants (`serde-json` vs `serde_json`) — score 2
   - legitimate derivatives (`tokio-util`, `serde_derive`, `axum-core`) are
     allowlisted and not flagged

Every hit is explainable: reason + score, so it is auditable, not a black
box. Run `--strict` to treat typosquat warnings as errors in CI.

## Usage

```sh
python3 scan.py [path/to/Cargo.lock ...]   # defaults to ./Cargo.lock
python3 scan.py --strict [Cargo.lock ...]  # typos = CI failure
python3 typosquat.py serde2 tokio-util     # check individual crate names
```

Exit 1 if compromised versions are found (or, with `--strict`, typosquat
warnings); 0 otherwise.

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

## Why this matters for agents

Dependency poisoning is a primary vector for compromising agent toolchains:
CI runs fetch crates with build scripts (`proc-macro1` shipped malicious
build.rs), and typosquats prey on the same human/agent fallibility that
`install a package` auto-completion does. Scanning lockfiles offline before
every build closes that door without adding a network dependency.

## Tests

```sh
python3 -m unittest test_typosquat   # 21 tests: real patterns + false positives
python3 -m unittest test_advisories  # advisory-db cross-reference tests
```

## Usage in CI / cron

```sh
python3 scan.py Cargo.lock || echo "malware hit"
python3 advisories.py Cargo.lock --db /var/cache/rustlock.json || echo "vulns found"
```