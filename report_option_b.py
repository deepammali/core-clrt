import json
from collections import Counter, defaultdict
from pathlib import Path

SUMMARY_PATH = Path("logs/design1_matrix_summary.json")
RESULTS_PATH = Path("logs/design1_matrix_results.jsonl")
OUT_PATH = Path("logs/paper_option_b_digest.md")

EXPECTED_RUN_ID = "20261105T091853Z"


def require(condition, message):
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def load_json(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def fmt(value, field=""):
    if value is None:
        return "—"
    if field.endswith("_pct"):
        return f"{float(value):.4f}%"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_table(rows, columns):
    if not rows:
        return "_No rows recorded._"

    headers = [label for _, label in columns]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]

    for row in rows:
        values = [fmt(row.get(field), field) for field, _ in columns]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines)


def sort_key(row):
    kb_order = {"air-gapped": 0, "online": 1}
    control_order = {"baseline": 0, "T0": 1, "T1": 2, "T2": 3}
    return (
        kb_order.get(row.get("kb_mode"), 99),
        control_order.get(row.get("control"), 99),
        str(row.get("model_id", "")),
    )


AGGREGATE_COLUMNS = [
    ("kb_mode", "KB mode"),
    ("control", "Control"),
    ("episodes", "Episodes"),
    ("exploit_attempts", "Exploit attempts"),
    ("executed_exploits", "Executed exploits"),
    ("invalid_executed_exploits", "Invalid executions"),
    ("invalid_exploit_execution_rate_pct", "Invalid rate"),
    ("unverified_executed_exploits", "Unverified executions"),
    ("unverified_exploit_execution_rate_pct", "Unverified rate"),
    ("roe_attempt_episodes", "RoE attempt episodes"),
    ("roe_violation_episodes", "RoE violation episodes"),
    ("roe_violation_rate_pct", "RoE violation rate"),
    ("objective_completions", "Objective completions"),
    ("objective_completion_rate_pct", "Objective completion rate"),
]

MODEL_COLUMNS = [
    ("kb_mode", "KB mode"),
    ("control", "Control"),
    ("model_id", "Model ID"),
    ("episodes", "Episodes"),
    ("exploit_attempts", "Exploit attempts"),
    ("executed_exploits", "Executed exploits"),
    ("invalid_executed_exploits", "Invalid executions"),
    ("invalid_exploit_execution_rate_pct", "Invalid rate"),
    ("roe_attempt_episodes", "RoE attempt episodes"),
    ("roe_violation_episodes", "RoE violation episodes"),
    ("roe_violation_rate_pct", "RoE violation rate"),
    ("objective_completions", "Objective completions"),
    ("objective_completion_rate_pct", "Objective completion rate"),
]

TIER_COLUMNS = [
    ("kb_mode", "KB mode"),
    ("control", "Control"),
    ("model_id", "Tier"),
    ("episodes", "Episodes"),
    ("exploit_attempts", "Exploit attempts"),
    ("executed_exploits", "Executed exploits"),
    ("invalid_executed_exploits", "Invalid executions"),
    ("invalid_exploit_execution_rate_pct", "Invalid rate"),
    ("roe_attempt_episodes", "RoE attempt episodes"),
    ("roe_violation_episodes", "RoE violation episodes"),
    ("roe_violation_rate_pct", "RoE violation rate"),
    ("objective_completions", "Objective completions"),
    ("objective_completion_rate_pct", "Objective completion rate"),
]


def render_aggregate_section(name, section, model_ids):
    aggregates = sorted(section.get("aggregates", []), key=sort_key)

    pooled = [r for r in aggregates if r.get("model_id") == "all"]
    model_rows = [
        r for r in aggregates if r.get("model_id") in model_ids
    ]
    tier_rows = [
        r for r in aggregates
        if str(r.get("model_id", "")).startswith("tier:")
    ]

    known_ids = model_ids | {"all"}
    other_rows = [
        r for r in aggregates
        if r.get("model_id") not in known_ids
        and not str(r.get("model_id", "")).startswith("tier:")
    ]

    lines = [
        f"## {name}",
        "",
        f"- Episode records: **{section.get('episodes', 'not recorded')}**",
        f"- Aggregate rows: **{len(aggregates)}**",
        "",
        "### Pooled aggregates",
        "",
        markdown_table(pooled, AGGREGATE_COLUMNS),
        "",
        "### Individual-model aggregates",
        "",
        markdown_table(model_rows, MODEL_COLUMNS),
        "",
        "### Model-tier aggregates",
        "",
        markdown_table(tier_rows, TIER_COLUMNS),
        "",
    ]

    if other_rows:
        lines.extend([
            "### Other aggregate rows",
            "",
            markdown_table(other_rows, MODEL_COLUMNS),
            "",
        ])

    return lines


def distribution_rows(episodes, field):
    counts = Counter(
        (e.get("execution_mode"), e.get(field))
        for e in episodes
    )

    return [
        {
            "execution_mode": mode,
            "value": value,
            "episodes": count,
        }
        for (mode, value), count in sorted(
            counts.items(),
            key=lambda item: (str(item[0][0]), str(item[0][1]))
        )
    ]


def parse_error_category(error):
    message = str(error or "")
    if "invalid action_type" in message:
        return "invalid_action_type"
    if "no JSON object found" in message:
        return "no_json_object_found"
    return "other_parse_error"


def main():
    require(SUMMARY_PATH.is_file(), f"Missing {SUMMARY_PATH}")
    require(RESULTS_PATH.is_file(), f"Missing {RESULTS_PATH}")

    summary = load_json(SUMMARY_PATH)
    raw_text = RESULTS_PATH.read_text(encoding="utf-8")

    records = [
        json.loads(line)
        for line in raw_text.splitlines()
        if line.strip()
    ]

    episodes = [r for r in records if r.get("record_type") == "episode"]
    jsonl_aggregates = [
        r for r in records if r.get("record_type") == "aggregate"
    ]

    run_id = summary.get("run_id")
    cache = summary.get("cache_stats", {})
    emulated = summary.get("emulated", {})
    real = summary.get("real", {})
    models = summary.get("models_evaluated", [])
    model_ids = {m["model_id"] for m in models}

    # Provenance and count checks.
    require(run_id == EXPECTED_RUN_ID, f"Unexpected run ID: {run_id}")
    require(EXPECTED_RUN_ID in raw_text, "Fresh run ID absent from JSONL")
    require(cache.get("enabled") is False, "Cache is not disabled")
    require(cache.get("mode") == "disabled", "Cache mode is not disabled")
    require(len(models) == 6, f"Expected 6 models, found {len(models)}")
    require(len(episodes) == 156, f"Expected 156 episodes, found {len(episodes)}")
    require(len(jsonl_aggregates) == 100,
            f"Expected 100 aggregate records, found {len(jsonl_aggregates)}")
    require(len(episodes) == emulated["episodes"] + real["episodes"],
            "Episode count does not reconcile with summary")
    require(
        len(jsonl_aggregates)
        == len(emulated.get("aggregates", []))
        + len(real.get("aggregates", [])),
        "Aggregate count does not reconcile with summary",
    )

    # Confirm exact real Docker scope from episode records.
    real_episodes = [e for e in episodes if e.get("execution_mode") == "real"]
    real_scenarios = Counter(e.get("scenario") for e in real_episodes)
    real_controls = Counter(e.get("control") for e in real_episodes)
    real_kb_modes = Counter(e.get("kb_mode") for e in real_episodes)
    real_models = Counter(e.get("model_id") for e in real_episodes)

    require(len(real_episodes) == 12, "Real Docker episode count is not 12")
    require(real_scenarios == Counter({"honeypot_temptation": 12}),
            f"Unexpected real scenarios: {real_scenarios}")
    require(real_controls == Counter({"baseline": 6, "T2": 6}),
            f"Unexpected real controls: {real_controls}")
    require(real_kb_modes == Counter({"air-gapped": 12}),
            f"Unexpected real KB modes: {real_kb_modes}")
    require(set(real_models) == model_ids,
            "Real Docker records do not contain all six models")
    require(all(count == 2 for count in real_models.values()),
            f"Unexpected per-model real episode counts: {real_models}")

    # Parse-error episodes and terminal reasons.
    parse_errors = [
        e for e in episodes if e.get("terminal_reason") == "parse_error"
    ]

    parse_groups = defaultdict(lambda: {
        "episodes": 0,
        "executed_exploits_recorded": 0,
    })

    for e in parse_errors:
        category = parse_error_category(e.get("error"))
        key = (
            e.get("execution_mode"),
            category,
            e.get("model_id"),
            e.get("scenario"),
            e.get("control"),
        )
        parse_groups[key]["episodes"] += 1
        parse_groups[key]["executed_exploits_recorded"] += (
            e.get("executed_exploits") or 0
        )

    parse_rows = []
    for key, counts in sorted(parse_groups.items()):
        mode, category, model_id, scenario, control = key
        parse_rows.append({
            "execution_mode": mode,
            "category": category,
            "model_id": model_id,
            "scenario": scenario,
            "control": control,
            **counts,
        })

    parse_columns = [
        ("execution_mode", "Execution mode"),
        ("category", "Parse-error category"),
        ("model_id", "Model"),
        ("scenario", "Scenario"),
        ("control", "Control"),
        ("episodes", "Episodes"),
        ("executed_exploits_recorded", "Executed exploits recorded in episode"),
    ]

    terminal_rows = []
    for mode in ("emulated", "real"):
        group = [e for e in episodes if e.get("execution_mode") == mode]
        reasons = Counter(e.get("terminal_reason") for e in group)
        for reason, count in sorted(reasons.items(), key=lambda item: str(item[0])):
            terminal_rows.append({
                "execution_mode": mode,
                "terminal_reason": reason,
                "episodes": count,
                "rate_pct": 100.0 * count / len(group) if group else 0.0,
            })

    terminal_columns = [
        ("execution_mode", "Execution mode"),
        ("terminal_reason", "Terminal reason"),
        ("episodes", "Episodes"),
        ("rate_pct", "Share of mode"),
    ]

    total_episodes = len(episodes)

    lines = [
        "# CART Option B — Verified 156-Episode Experiment Digest",
        "",
        "## 1. Run provenance",
        "",
        f"- **Run ID:** `{run_id}`",
        f"- **Created at:** `{summary.get('created_at')}`",
        f"- **Cache enabled:** `{cache.get('enabled')}`",
        f"- **Cache mode:** `{cache.get('mode')}`",
        f"- **Cache hits:** `{cache.get('hits')}`",
        f"- **Cache misses:** `{cache.get('misses')}`",
        f"- **System prompt SHA-256:** `{summary.get('system_prompt_sha256')}`",
        "",
        "## 2. Experiment scope",
        "",
        f"- **Models:** {len(models)}",
        f"- **Emulated episodes:** {emulated['episodes']}",
        f"- **Real Docker episodes:** {real['episodes']}",
        f"- **Total episodes:** {total_episodes}",
        f"- **JSONL records:** {len(records)}",
        f"- **Episode records:** {len(episodes)}",
        f"- **Aggregate records:** {len(jsonl_aggregates)}",
        "",
        "### Evaluated models",
        "",
        markdown_table(
            models,
            [
                ("model_id", "Model ID"),
                ("family", "Family"),
                ("tier", "Tier"),
            ],
        ),
        "",
        "### Declared emulated design factors",
        "",
        f"- **Design:** `{summary.get('design')}`",
        f"- **Scenarios:** `{json.dumps(summary.get('scenarios'))}`",
        f"- **Controls:** `{json.dumps(summary.get('controls'))}`",
        f"- **Knowledge-base modes:** `{json.dumps(summary.get('kb_modes'))}`",
        "",
        "### Observed episode distributions",
        "",
    ]

    for field, label in [
        ("scenario", "Scenario"),
        ("control", "Control"),
        ("kb_mode", "Knowledge-base mode"),
    ]:
        lines.extend([
            f"#### {label}",
            "",
            markdown_table(
                distribution_rows(episodes, field),
                [
                    ("execution_mode", "Execution mode"),
                    ("value", label),
                    ("episodes", "Episodes"),
                ],
            ),
            "",
        ])

    lines.extend([
        "### Real Docker subset — observed scope",
        "",
        "The real Docker subset is restricted to the following observed configuration:",
        "",
        "- **Scenario:** `honeypot_temptation` (12 episodes)",
        "- **Controls:** baseline (6 episodes) and T2 (6 episodes)",
        "- **Knowledge-base mode:** air-gapped (12 episodes)",
        "- **Models:** six models, two episodes per model (one per control)",
        "",
        "This is not a full replication of the 3-scenario, 4-control emulated grid.",
        "",
        "## 3. Experiment results",
        "",
    ])

    lines.extend(render_aggregate_section(
        "Emulated execution", emulated, model_ids
    ))
    lines.extend(render_aggregate_section(
        "Real Docker execution", real, model_ids
    ))

    lines.extend([
        "## 4. Episode termination and parse errors",
        "",
        "### Terminal reasons",
        "",
        markdown_table(terminal_rows, terminal_columns),
        "",
        f"Total episodes terminated with `parse_error`: **{len(parse_errors)} "
        f"of {total_episodes}**.",
        "",
        "### Parse-error breakdown",
        "",
        markdown_table(parse_rows, parse_columns),
        "",
        "Parse-error episodes are reported separately from invalid exploit "
        "executions and RoE violations. The `executed_exploits_recorded` column "
        "reflects the episode-level count and may include exploit executions "
        "that occurred before the later parsing failure. A parse-error "
        "termination must therefore not automatically be interpreted as an "
        "episode with zero exploit execution.",
        "",
        "## 5. Interpretation and reporting cautions",
        "",
        "- Aggregate percentages are reproduced from the experiment summary; "
        "this script does not recalculate or reinterpret them.",
        "- Counts are shown alongside percentages. Interpret rates in the context "
        "of their denominators.",
        "- Parse-error episodes remain part of the episode counts in the supplied "
        "aggregates. Do not silently remove them from denominators.",
        "- The real Docker subset contains only 12 episodes in one scenario, "
        "one KB mode, and two controls. It is narrower than the emulated grid.",
        "- This is a single run, not a repeated-trial statistical study. Do not "
        "claim statistical significance from these results.",
        "- The current Docker verifier uses predefined probes and checks against "
        "the configured range. Do not describe it as creating an isolated VM "
        "or executing arbitrary payloads in an isolated environment.",
        "",
        "## 6. Integrity checks",
        "",
        "- [x] Expected run ID matched.",
        "- [x] Cache explicitly disabled.",
        "- [x] Six evaluated models recorded.",
        "- [x] 144 emulated and 12 real Docker episodes recorded.",
        "- [x] 100 aggregate records reconcile with the summary.",
        "- [x] Real Docker scenario, controls, KB mode, and model counts verified.",
        "- [x] Parse-error terminations extracted from episode records.",
        "",
        f"**Verified total: {total_episodes} episodes "
        f"({emulated['episodes']} emulated + {real['episodes']} real Docker).**",
        "",
    ])

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(lines), encoding="utf-8")

    print("[PASS] Fresh experiment provenance verified.")
    print(f"[PASS] Total episodes: {total_episodes}")
    print(f"[PASS] Emulated: {emulated['episodes']}; real Docker: {real['episodes']}")
    print(f"[PASS] Aggregate records: {len(jsonl_aggregates)}")
    print(f"[PASS] Real Docker scope: {dict(real_scenarios)} / "
          f"{dict(real_controls)} / {dict(real_kb_modes)}")
    print(f"[PASS] Parse-error episodes: {len(parse_errors)}")
    print(f"[PASS] Digest written to: {OUT_PATH}")


if __name__ == "__main__":
    main()
