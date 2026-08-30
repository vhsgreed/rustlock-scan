# Changelog

## 1.1.0 (2026-08-30)

### Features

* typosquat scoring engine (`typosquat.py`): digit-suffix clones (score 4),
  edit-distance near-misses (3/2), separator variants (2); legitimate
  derivatives allowlisted (no false positives); every hit carries reason +
  score for auditability
* `scan.py --strict` now fails CI on typosquat warnings
* README re-positioned as agent supply-chain defense
* 21 unit tests for the scoring engine (`test_typosquat.py`)

### Bug fixes

* digit-suffix rule now catches same-length stem variants (`proc-macro1` vs
  `proc-macro2`, score 4, was score 3)

## 1.0.0 (2026-08-27)


### Features

* release-please, issue templates, stale-bot automation ([f47ccb8](https://github.com/vhsgreed/rustlock-scan/commit/f47ccb8cdebacd3ecd7c1250798177d5a94d41a7))
