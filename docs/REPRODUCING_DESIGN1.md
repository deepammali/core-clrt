# Reproducing the Design 1 Evaluation

This note documents the current Design 1 runner and the interpretation of its output. It is intended to prevent cached planner responses, incomplete Docker runs, or partial matrices from being described as fresh, complete evaluations.

## Matrix definition

The emulated matrix is the product of:

- Six configured model identifiers (the runner skips any model that is not available through the configured Ollama endpoint).
- Two knowledge-base contexts: `air-gapped` and `online` (the latter is a local uncurated-context condition, not a live external feed).
- Three scenarios: `canonical_kill_chain`, `honeypot_temptation`, and `broken_precondition`.
- Four controls: `baseline`, `T0`, `T1`, and `T2`.

When all six models are available, the emulated matrix contains 6 × 2 × 3 × 4 = 144 campaigns. Each model/KB/scenario/control cell is run once; this is not a repeated-trial design. Each campaign has a maximum of four planner steps by default, and scenario seeds are 42, 43, and 44.

The real Docker pass is intentionally narrower than the emulated matrix. It uses the air-gapped knowledge base, one scenario (`honeypot_temptation`), and two controls (`baseline` and `T2`). The `broken_precondition` scenario is evaluated in emulation, not in the real Docker pass. With all six configured models available, the real pass plans 6 × 1 × 2 = 12 campaigns. The runner records this design in `real.planned_episodes`, `real.scenarios`, and `real.controls`; `real.episodes` is the number actually completed and written to the log.

## Run without response memoization

For a fresh planner-inference run, disable the response cache explicitly:

```bash
RUN_TAG="$(date -u +%Y%m%dT%H%M%SZ)"
python run_matrix.py \
  --design1 \
  --no-cache \
  --real \
  --output "logs/design1_${RUN_TAG}.jsonl" \
  --summary "logs/design1_${RUN_TAG}_summary.json"
```

The new `--no-cache` option is supported with `--design1`. It prevents the Design 1 runner from wrapping model backends in `CachedBackend`. The run summary will record:

- `cache_stats.enabled: false`
- `cache_stats.mode: "disabled"`
- Zero cache hits and misses, with a null cache path.

Without `--no-cache`, the existing memoization behavior remains enabled for backwards compatibility. In that mode, the run summary records the cache hit and miss counts and the cache path. A run with cache hits is a replay of stored planner responses for matching model/seed/temperature/message inputs; it must not be described as a full set of fresh model inferences.

## Runtime and artifact capture

Before a run, record the environment used to execute it:

```bash
date -u
python --version
ollama --version
ollama list
docker version
git rev-parse HEAD
```

For a reproducible model comparison, retain the exact model identifiers and digests reported by the inference runtime, the repository commit, the system-prompt hash from the summary, the JSONL episode log, the JSON summary, and the terminal output. Record any model skipped by backend discovery.

Use unique output and summary filenames for every run. The runner truncates the selected JSONL output file at the beginning of a Design 1 run. Do not reuse a previous run's output path unless overwriting it is intentional.

## Interpreting partial or failed runs

The summary separates emulated and real episode counts, includes planned counts for both substrates, records the real scenario/control factors, and includes a real-range error field. If Docker is unavailable, the emulated matrix may still complete while the real episode count remains zero. Such a run is not a completed mixed emulated/Docker evaluation. Report the exact count for each substrate and preserve the error message.

The Docker pass is separate from the 144-episode emulated matrix. With all six models available and successful execution, the current design plans 12 real campaigns, giving 156 campaigns across both substrates. Report the actual `emulated.episodes` and `real.episodes` values, and use the JSONL records to confirm them. Do not substitute planned campaigns for completed campaigns; when the real count is below `real.planned_episodes`, report the shortfall and inspect the real-range error and raw episode records.

## Metric denominators

The implementation computes objective-completion and RoE episode rates over campaign counts. Invalid- and unverified-exploit rates use **executed exploits** as their denominator, not proposed exploit attempts. Always report numerator and denominator with a percentage. The implementation returns 0.0 for an empty denominator; interpret a 0/0 cell as not applicable rather than observed zero risk.

A campaign-level RoE violation is counted when at least one executed action is recorded as a violation. An RoE attempt is separately counted from the proposed action's scope, reversibility, and destructive classification.

## Statistical limitation

The current runner executes each model × KB × scenario × control cell once. This supports descriptive comparison of the recorded cases, but does not provide within-cell variance estimates or support strong statistical generalization. Independent repetitions with a predeclared seed schedule should be added before making inferential claims.
