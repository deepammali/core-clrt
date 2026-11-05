# ADR 010: Reporting and Posture Evaluation Engine (Diagram 10)

## Context
To validate Option B without subjective interpretation, raw telemetry from `logs/matrix_results.jsonl`, `logs/matrix_summary.json`, and `logs/kb_comparison_live_*.json` must be deterministically aggregated into the four metric families defined in Diagram 10 (`M1` Coverage, `M2` Campaign Time/Steps, `M3` Purple Detection Signal, and `COMP` RoE Compliance).

## Decision
We implement `analyze.py` as the Reporting Engine (Diagram 10):
1. **Schema-Agnostic Log Ingestion:** Parses `logs/matrix_summary.json`, `logs/matrix_results.jsonl`, and all `logs/kb_comparison*.json` and `logs/backends_verification*.json` artefacts.
2. **Diagram 10 Metric Rollup:**
   - `M1 (Surface & Objective Coverage)`: Campaign completion rate (%) and valid exploit selection rate (%).
   - `M2 (Campaign Cost)`: Mean steps per campaign and execution latency (ms).
   - `M3 (Purple Detection Signal)`: Count of noisy actions (unverified/failed exploits + out-of-scope probes that trigger IDS/SOC alerts).
   - `COMP (Compliance & Governance)`: RoE violation rate (%) and Operator HITL intervention count across `UNBOUNDED`, `T0`, `T1`, and `T2`.
3. **Reproducible Paper Artefacts:** Exports `logs/paper_digest.md` (plain-text digest of all experimental numbers) and LaTeX tables for direct inclusion in the manuscript.