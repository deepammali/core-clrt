# CART Core Decisions

Date: 2026-11-03
Status: accepted for implementation

This folder records the concrete decisions used by `range_emulator.py`,
`executor.py`, `gate.py`, `backends.py`, `kb_store.py`, the Docker range, and
their tests. Each record is specific about addresses, models, credentials,
container names, ports, timeouts, trust thresholds, and test contracts so the
benchmark can be reproduced.

| Decision | File | Summary |
|---|---|---|
| 001 | `001-benchmark-scenarios.md` | One A-D topology, three benchmark scenarios |
| 002 | `002-execution-mode-switch.md` | Emulated vs real switch and `vm_verified` semantics |
| 003 | `003-real-docker-range.md` | Two-container Docker range and probe design |
| 004 | `004-verification-gate.md` | Valid/invalid parity test contract |
| 005 | `005-failure-fallback.md` | Docker-unavailable fallback and environment switches |
| 006 | `006-cve-and-credential-mapping.md` | Exact CVE, grant, and credential mapping |
| 007 | `007-roe-autonomy-gate.md` | RoE/autonomy gate, CIDR scope, simulated operator |
| 008 | `008-llm-backends.md` | Unified tool-call backends and live 3-model gate |
| 009 | `009-signed-kb.md` | Signed KB, trust filtering, 20 distractors, uncurated baseline |
