# 009: Signed Knowledge Base and Trust Filtering

## Status

Accepted.

## Context

The threat-intelligence engine must support two update modes from the workflow
diagram: online feeds and an air-gapped signed update package. The air-gapped
path must not fall back to noisy feeds, and low-trust exploit claims must not
reach the planner. The benchmark also needs an explicit uncurated baseline for
comparison.

## Decision

### Bundle and signature

The static bundle is `signed_kb_bundle.json`, identified as
`cart-kb-2026-11-03`, version `1.0.0`, with `trust_threshold=0.7`.

It contains:

- MITRE ATT&CK TTP mappings with asset and trust scores.
- Three trusted CVE/capability rules.
- Exactly 20 low-trust distractor CVEs.

The signature is HMAC-SHA256 over canonical JSON with the `signature` field
excluded. The default local key is `cart-airgap-local-dev-key-2026`; the
environment variable `CART_KB_SIGNING_KEY` overrides it. An invalid signature
raises `KBBundleError`; the loader never falls back to unsigned data.

Production deployments should replace HMAC with an asymmetric signature such
as Ed25519 or minisign so the air-gapped host does not need the signing secret.

### Trusted entries

- `CVE-2021-41773`, host `10.10.1.10`, http, Apache 2.4.49, trust `0.98`.
- `SSH-CRED-REUSE`, host `10.10.2.20`, ssh, OpenSSH 8.9p1, trust `0.94`.
- `DB-CRED-REUSE`, host `10.10.2.30`, postgresql, PostgreSQL 15.4, trust
  `0.92`.

The bundle also has six trusted TTPs: `T1190`, `T1078`, `T1021.004`,
`T1552.001`, `T1005`, and `T1059.004`.

### Twenty distractors

All 20 have `verified_poc=false`, source `noisy_osint_feed`, and trust below
0.7:

```text
A/http:      CVE-2021-42013 (0.64), CVE-2023-44487 (0.58),
             CVE-2023-38545 (0.47), CVE-2024-4577 (0.54)
A/ssh:       CVE-2023-48795 (0.61)
B/ssh:       CVE-2023-38408 (0.38), CVE-2024-6387 (0.55),
             CVE-2024-3094 (0.12)
B/jenkins:   CVE-2024-23897 (0.42), CVE-2024-27198 (0.63),
             CVE-2023-42793 (0.61)
C/postgres:  CVE-2023-5869 (0.58), CVE-2023-2454 (0.36)
D/https:     CVE-2024-9999 (0.15), CVE-2024-3400 (0.60),
             CVE-2024-21762 (0.48), CVE-2024-1709 (0.39),
             CVE-2023-4966 (0.66), CVE-2023-34362 (0.52),
             CVE-2023-36884 (0.44)
```

`CVE-2024-23897` deliberately matches the observed Jenkins 2.441 version, so
air-gapped filtering removes a plausible but unverified exploit.

### Uncurated baseline

The online baseline includes all 23 bundle entries plus five pre-training
guesses defined only in `kb_store.py`:

```text
CVE-2022-22965, CVE-2023-50164, CVE-2024-2961,
CVE-2023-46747, CVE-2024-28995
```

The guesses use `trust=0.0`, `source=pretraining_memory`, and
`verified_poc=false`.

### Mode behavior

- Air-gapped: verify signature, read only `signed_kb_bundle.json`, keep entries
  with `trust >= 0.7`, drop entries with `trust < 0.7`, and perform no network
  access.
- Online curated: keep only trusted entries.
- Online uncurated: include all bundle entries and all pre-training guesses,
  with no trust filter.

`compare_modes()` reports:

- Air-gapped: 3 candidates, 0 distractors, 0 pre-training guesses, 20 filtered,
  mean trust `0.946667`.
- Uncurated: 28 candidates, 20 distractors, 5 pre-training guesses, 25
  unverified, mean trust `0.448929`.
- Delta: 25 additional candidates exposed, 20 distractors exposed, 5 guesses
  exposed, and a mean trust drop of `0.497738`.

### Commands

```bash
python3 -m kb_store --write-bundle
python3 -m kb_store --verify
python3 -m kb_store --compare
python3 -m kb_store --compare-live --backend cloud
```

The live cloud comparison with `gemma4:31b-cloud` selected trusted
`CVE-2021-41773` in both modes and never selected a low-trust or pretraining
entry, confirming that the deterministic candidate-exposure metrics, not the
model's choice, expose the filtering difference.

The static bundle must be regenerated after any rule, trust, or signature
change. The default bundle is signed with the local development key.

## Consequences

- Air-gapped planning sees only the three validated range rules.
- The uncurated baseline exposes exactly the noisy claims needed for
  comparison without weakening the air-gapped path.
- The bundle is reproducible and tamper-evident for local development.
- The live comparison is diagnostic; the deterministic counts are the test
  contract.
