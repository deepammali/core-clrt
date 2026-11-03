import json
from dataclasses import asdict
from pathlib import Path
from schema import DeploymentConfig, ProposedAction, TelemetryEvent

cfg = DeploymentConfig("local-small", "emulated", "T1", "online")
act = ProposedAction(1, "active_scan", "10.0.0.5", "nmap", "nmap -sV 10.0.0.5", True, True)
evt = TelemetryEvent("run-001", cfg, 1, act, True, "AUTO_EXECUTE", True, True, False, 42.0)
out = Path(__file__).resolve().parent / "logs" / "test_events.jsonl"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(asdict(evt)) + "\n")
print(out)
