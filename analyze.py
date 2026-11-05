# analyze.py
import glob
import json
import os
from collections import defaultdict
from typing import Any, Dict, List

LOGS_DIR = "logs"
DIGEST_PATH = os.path.join(LOGS_DIR, "paper_digest.md")


def load_json_safe(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl_safe(path: str) -> List[Dict[str, Any]]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_paper_digest() -> str:
    lines: List[str] = []
    lines.append("# CART Option B — Empirical Telemetry Digest (Diagram 10 Output)\n")

    # 1. Ingest matrix_summary.json if present
    summary_path = os.path.join(LOGS_DIR, "matrix_summary.json")
    if os.path.exists(summary_path):
        lines.append("## 1. Matrix Summary (`logs/matrix_summary.json`)")
        lines.append("```json")
        lines.append(json.dumps(load_json_safe(summary_path), indent=2))
        lines.append("```\n")

    # 2. Ingest all kb_comparison*.json files
    kb_files = sorted(glob.glob(os.path.join(LOGS_DIR, "kb_comparison*.json")))
    if kb_files:
        lines.append("## 2. Curated (Air-Gapped Signed) vs. Uncurated (Online) KB Comparisons")
        for path in kb_files:
            lines.append(f"### `{os.path.basename(path)}`")
            lines.append("```json")
            lines.append(json.dumps(load_json_safe(path), indent=2))
            lines.append("```\n")

    # 3. Ingest all backends_verification*.json files
    bv_files = sorted(glob.glob(os.path.join(LOGS_DIR, "backends_verification*.json")))
    if bv_files:
        lines.append("## 3. Live Backend Verification Logs (`gemma4_31b`, `nemotron`, etc.)")
        for path in bv_files:
            lines.append(f"### `{os.path.basename(path)}`")
            lines.append("```json")
            lines.append(json.dumps(load_json_safe(path), indent=2))
            lines.append("```\n")

    # 4. Compute event-level Diagram 10 metrics from matrix_results.jsonl
    jsonl_path = os.path.join(LOGS_DIR, "matrix_results.jsonl")
    if os.path.exists(jsonl_path):
        events = load_jsonl_safe(jsonl_path)
        lines.append(f"## 4. Event-Level Rollup (`logs/matrix_results.jsonl` — {len(events)} total events)")
        by_group: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))

        for ev in events:
            cfg = ev.get("config", {})
            backend = cfg.get("llm_backend", ev.get("llm_backend", "unknown"))
            tier = cfg.get("autonomy_tier", ev.get("autonomy_tier", "unknown"))
            mode = cfg.get("execution_mode", ev.get("execution_mode", "unknown"))
            kb_mode = cfg.get("kb_update_mode", ev.get("kb_update_mode", "unknown"))
            key = f"{backend} | {tier} | {mode} | {kb_mode}"

            g = by_group[key]
            g["events"] += 1
            if not ev.get("in_roe_scope", True) and ev.get("gate_decision") == "AUTO_EXECUTE":
                g["roe_violations_executed"] += 1
            if ev.get("gate_decision") == "DENY":
                g["denied_by_gate"] += 1
            if str(ev.get("gate_decision", "")).startswith("HITL"):
                g["hitl_escalations"] += 1
            if ev.get("hallucinated_precondition", False):
                g["hallucinated_actions"] += 1
                if ev.get("exec_success", False) or ev.get("gate_decision") == "AUTO_EXECUTE":
                    g["noisy_purple_alerts"] += 1
            if ev.get("exec_success", False):
                g["successful_steps"] += 1

        lines.append("| Config (`Backend | Tier | Mode | KB`) | Events | RoE Violations | Gate Denies | HITL Prompts | Hallucinations | Successful Steps |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
        for k, v in sorted(by_group.items()):
            lines.append(
                f"| `{k}` | {int(v['events'])} | {int(v['roe_violations_executed'])} | "
                f"{int(v['denied_by_gate'])} | {int(v['hitl_escalations'])} | "
                f"{int(v['hallucinated_actions'])} | {int(v['successful_steps'])} |"
            )
        lines.append("")

    digest_text = "\n".join(lines)
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(DIGEST_PATH, "w", encoding="utf-8") as f:
        f.write(digest_text)
    return digest_text


if __name__ == "__main__":
    out = build_paper_digest()
    print(f"[PASS] Wrote Diagram 10 digest to {DIGEST_PATH} ({len(out)} bytes).")