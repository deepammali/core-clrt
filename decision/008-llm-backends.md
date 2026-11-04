# 008: Unified LLM Backends and Three-Model Verification Gate

## Status

Accepted.

## Context

Mission planning must compare local-small, local-large, and cloud planners
without changing the prompt or the action contract. The host has
`qwen2.5-coder:7b`, `gemma4:e4b-mlx`, and `qwen2.5-coder:14b`; the 14B model
was skipped because it saturates the workstation during generation. The older
`deepseek-v4-flash:cloud` model was retired. The gate must also avoid silently
retrying malformed model output.

## Decision

### Models and providers

- `local-small`: `qwen2.5-coder:7b` through Ollama.
- `local-large`: `gemma4:e4b-mlx` (8.1B, MLX/NVFP4) through Ollama. The 14B
  model is skipped on this host.
- `cloud` default: `gemma4:31b-cloud` (32.7B BF16, 262k context,
  thinking/tools/vision).
- Cloud overrides: `nemotron-3-super:cloud` (120B) for the higher-capability
  baseline, `deepseek-v4-pro:cloud` (1.65T) for a frontier baseline, or an
  OpenAI-compatible endpoint via `CART_CLOUD_PROVIDER=openai`.
- `deepseek-v4-flash:cloud` is retired and must not be used.
- The default cloud model is deliberately 32.7B and is below the earlier 120B
  baseline. This is a cost/latency tradeoff; `nemotron-3-super:cloud` remains
  available for a higher-capability comparison.

The live gate runs with `qwen2.5-coder:7b`, `gemma4:e4b-mlx`, and
`gemma4:31b-cloud`. This validates the three-backend interface, shared
prompt/state, parsing, and logging without saturating the workstation. It does
not validate the 14B model's planning quality. On hardware that can run the
14B model, set `CART_LOCAL_LARGE_MODEL=qwen2.5-coder:14b`.

Ollama uses `POST /api/chat` with `stream=false`, `format=json`,
`think=false`, `temperature=0`, `seed=42`, and `num_predict=512`.
Disabling thinking prevents reasoning tokens from consuming the JSON budget.
OpenAI-compatible backends
use `POST /v1/chat/completions` with `response_format={"type":"json_object"}`,
`temperature=0`, and `max_tokens=512`.

Environment overrides:

```text
CART_OLLAMA_URL
CART_LOCAL_SMALL_MODEL
CART_LOCAL_LARGE_MODEL
CART_CLOUD_PROVIDER       ollama | openai
CART_CLOUD_MODEL
CART_CLOUD_BASE_URL
CART_CLOUD_API_KEY
```

### Shared action contract

Every backend receives the same `SYSTEM_PROMPT` and the same serialized graph
state. The model returns exactly:

```json
{
  "action_type": "passive_recon|active_scan|exploit|post_ex_read|destructive",
  "target_ip": "<IPv4>",
  "cve_or_tool": "<non-empty string>",
  "payload_cmd": "<string>"
}
```

`ProposedAction` derives the remaining fields:

| `action_type` | `is_read_only` | `is_reversible` |
|---|---|---|
| `passive_recon` | true | true |
| `active_scan` | true | true |
| `exploit` | false | true unless payload is destructive |
| `post_ex_read` | true | true |
| `destructive` | false | false |

A conservative destructive-payload check marks `rm -rf`, `mkfs`, `dd if=`,
`shutdown`, `reboot`, `DROP TABLE`, and similar commands irreversible. The
parser does not enforce RoE scope; `gate.py` and `executor.py` remain the
authorities for scope and preconditions.

### Parsing and one-turn rule

- Accept raw JSON, fenced JSON, and prose-wrapped JSON.
- Require the four schema keys; reject missing keys, wrong types, invalid
  action types, non-IPv4 targets, and empty `cve_or_tool`.
- Normalize an empty `cve_or_tool` to `osint` only for `passive_recon`.
- Record extra keys but do not fail on them.
- Call each backend exactly once. No retries. A malformed response is logged
  and fails the gate.

### Verification gate

`python3 -m backends --verify` uses scenario `honeypot_temptation`, air-gapped
KB mode, one shared graph state, and one shared messages object. The log
records `system_prompt_sha256`, `messages_sha256`, `graph_state_sha256`, raw
output, parsed action, latency, and errors for all three backends. The log is
written to `logs/backends_verification.json`.

The live unittest is opt-in:

```bash
CART_LIVE_BACKENDS=1 python3 -m unittest -v test_backends.TestLiveBackends
```

For the skipped 14B hypothesis on capable hardware, override the model:

```bash
CART_LOCAL_LARGE_MODEL=qwen2.5-coder:14b \
CART_LIVE_BACKENDS=1 python3 -m unittest -v test_backends.TestLiveBackends
```

To restore the 120B cloud baseline:

```bash
CART_CLOUD_MODEL=nemotron-3-super:cloud \
CART_LIVE_BACKENDS=1 python3 -m unittest -v test_backends.TestLiveBackends
```

## Consequences

- No third-party HTTP client is required; the implementation uses
  `urllib.request`.
- The same prompt and schema are used for all three model classes.
- The gate distinguishes transport failure, malformed output, and out-of-scope
  planning; only the first two fail the parse gate.
- The local models must be pulled before the live gate can run.
- The default local-large is the 8.1B MLX model so the gate does not saturate
  the workstation; the 14B model is opt-in only.
- The default cloud model is 32.7B; the 120B `nemotron-3-super:cloud` baseline
  remains opt-in through `CART_CLOUD_MODEL`.
