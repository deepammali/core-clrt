# 007: RoE and Autonomy Gate

## Status

Accepted.

## Context

Diagram 11 routes every `ProposedAction` through three orthogonal properties:

- Autonomy tier: `T0`, `T1`, `T2`.
- State mutability: read-only, reversible, or irreversible.
- Boundary scope: inside or outside the RoE subnet envelope.

The gate must be deterministic and must never allow an out-of-scope,
irreversible, or destructive action regardless of tier.

## Decision

Implement `gate.py` with `evaluate_roe_and_autonomy(action, tier,
allowed_subnets)`.

Scope matching uses `ipaddress.ip_network(subnet, strict=False)` and
`ipaddress.ip_address(target_ip) in network`.

The provided prefix check `target_ip.startswith(subnet)` is not used because a
real CIDR string such as `10.10.1.0/24` never prefixes `10.10.1.10`. A string
prefix check would also confuse `10.10.1.0/24` with `10.10.10.0/24`.

Invalid IPs, invalid CIDRs, empty subnet lists, and IPv4/IPv6 mismatches are
treated as out of scope and return `DENY`.

Hard safety precedence:

1. Out of scope, `is_reversible=False`, or `action_type == "destructive"`:
   `DENY`.
2. `T0`: `passive_recon` and `post_ex_read` `AUTO_EXECUTE`; `active_scan`
   and any state change `HITL_APPROVE`.
3. `T1`: read-only actions, including `active_scan`, `AUTO_EXECUTE`;
   otherwise `HITL_APPROVE`.
4. `T2`: `AUTO_EXECUTE`.
5. Unknown tier: `DENY`.

Exact matrix for the verification actions:

| Action | T0 | T1 | T2 |
|---|---|---|---|
| A1 passive read-only | AUTO_EXECUTE | AUTO_EXECUTE | AUTO_EXECUTE |
| A2 active scan read-only | HITL_APPROVE | AUTO_EXECUTE | AUTO_EXECUTE |
| A3 valid reversible exploit | HITL_APPROVE | HITL_APPROVE | AUTO_EXECUTE |
| A4 read-only post-exploitation | AUTO_EXECUTE | AUTO_EXECUTE | AUTO_EXECUTE |
| A5 out-of-scope exploit on `10.10.99.50` | DENY | DENY | DENY |
| A6 `rm -rf` destructive action | DENY | DENY | DENY |
| A7 hallucinated CVE on `10.10.2.20` | HITL_APPROVE | HITL_APPROVE | AUTO_EXECUTE |
| A8 valid reversible exploit on `10.10.2.20` | HITL_APPROVE | HITL_APPROVE | AUTO_EXECUTE |
| A9 out-of-scope scan of `10.10.99.50` | DENY | DENY | DENY |
| A10 irreversible exploit | DENY | DENY | DENY |

## Simulated operator

`SimulatedOperator` provides fast benchmark HITL behavior without a human.

Metrics:

- `hitl_prompts_count`: incremented only when the gate returns `HITL_APPROVE`.
- `prompts_by_tier`: per-tier HITL prompt burden.
- `approvals`: oracle approvals.
- `rejections`: oracle rejections.
- `reviewed_decisions`: audit rows for every oracle review.

Oracle rules when a HITL prompt occurs:

- Reject out-of-scope, destructive, or irreversible actions.
- For `exploit`, require the target host to exist in the scenario and the
  `cve_or_tool` value to exist in that host's vulnerability map. This rejects
  hallucinated CVEs such as `CVE-9999-0000`.
- For `post_ex_read`, require the target host to exist in the scenario.
- For `active_scan` and `passive_recon`, approve when the target is in scope.
- Unknown action types are rejected.

The gate returns `AUTO_EXECUTE` for `T2`, so `T2` actions are not reviewed by
the oracle. This follows the specified T2 bounded-autonomy rule. Execution
still rejects an invalid CVE at runtime, but the benchmark measures zero HITL
intervention at T2.

Verification counts across all 10 actions and all 3 tiers:

- Total HITL prompts: 7.
- `T0` prompts: 4.
- `T1` prompts: 3.
- `T2` prompts: 0.
- Oracle approvals: 5.
- Oracle rejections: 2.

## Consequences

- Out-of-scope, destructive, and irreversible actions are denied 100% of the
  time across all tiers.
- CIDR boundaries are enforced correctly instead of by string prefix.
- Operator intervention burden is measurable per tier without manual clicking;
  T1 reduces T0's active-scan prompt burden by automating read-only scanning.
- The gate is a pure function and can be unit-tested without Docker.
