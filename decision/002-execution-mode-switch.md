# 002: Emulated vs Real Execution Switch

## Status

Accepted.

## Context

Running 90+ ablation trials against live virtual machines is slow and
brittle. A pure emulator alone does not answer the reviewer question: does the
same action work on real sockets?

## Decision

`DeploymentConfig.execution_mode` is the only switch.

`emulated`:

- Uses a pure Python state table keyed by `(target_ip, action_type,
  cve_or_tool)`.
- Returns deterministic nmap, curl, exploit, SSH, and psql output.
- Enforces RoE, reachability, CVE match, and credential preconditions.
- Performs no network I/O and no sleeps.
- Must complete an action in under 5 ms; `test_executor.py` asserts
  `max(latency_ms) < 5.0` over 100 actions.
- Sets `vm_verified=None` because no VM was used.

`real`:

- Uses the two-container Docker range from decision 003.
- Runs the isolated-VM verification probe with a 10 second timeout.
- Sets `vm_verified=True` only when the probe's HTTP marker or exit code
  confirms the exploit.
- Sets `vm_verified=False` for a wrong CVE, failed probe, or failed payload.
- Sets `vm_verified=None` for read-only scans and passive recon.
- Hard-denies out-of-scope targets before any Docker command runs.

## Consequences

- 90+ trials run in emulated mode for scale.
- Real mode is reserved for the Diagram 9 verification and the parity gate.
- The two modes share the same scenario, action schema, and success contract.
- Emulated and real success booleans are directly comparable.
