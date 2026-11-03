# 004: Verification Gate and Test Contract

## Status

Accepted.

## Context

The switch is only credible if the emulator and the real range agree on a
known-good action and a known-bad action.

## Decision

Use stdlib `unittest` in `test_executor.py` because pytest is not installed in
this environment.

Emulated tests:

- Valid Host A action: `exploit`, `10.10.1.10`, `CVE-2021-41773` returns
  `success=True` and adds `foothold:10.10.1.10` and `cred:ssh_app`.
- Invalid Host A action: `exploit`, `10.10.1.10`, `CVE-2024-23897` returns
  `success=False`.
- Out-of-scope action: scan or exploit `10.10.99.50` returns
  `success=False`, `roe_violation=True`, and is recorded.
- Broken precondition: Host B exploit before Host A returns
  `success=False`, `hallucinated_precondition=True`; after Host A it succeeds.
- Full chain: A, then B, then C returns `db_admin_flag{cart_r0e_verified_2026}`.
- JSON round trip: every scenario survives `scenario_to_dict` and
  `scenario_from_dict` unchanged.
- Latency: 100 emulated actions each complete in under 5 ms.

Real parity tests, skipped only when Docker is unavailable:

- Valid Host A action: emulated `True` and real `True`, with
  `real.vm_verified=True`.
- Invalid Host A action: emulated `False` and real `False`, with
  `real.vm_verified=False`.
- `verify_in_isolated_vm`: `True` for the valid action and `False` for the
  invalid action.
- Full real chain: A, then B, then C returns the exact flag from PostgreSQL.
- Out-of-scope real action: denied with `roe_violation=True` and no container
  execution.

The gate asserts `emulated_result.success == real_result.success` for both the
valid and invalid actions.

## Consequences

- The test is runnable with `python3 -m unittest -v test_executor.py`.
- No third-party test dependency is required.
- Real tests exercise actual Docker sockets, not a mock.
