from dataclasses import dataclass, field
from typing import Literal, Optional, List, Dict
import time

# 1. Operator Configuration Switches (Diagram 12)
@dataclass
class DeploymentConfig:
    llm_backend: Literal["local-small", "local-large", "cloud"]
    execution_mode: Literal["emulated", "real"]
    autonomy_tier: Literal["T0", "T1", "T2"]
    kb_update_mode: Literal["online", "air-gapped"]

# 2. Target Graph Fact (Diagram 13 - Pre-wired for Option A!)
@dataclass
class AssetFact:
    asset_id: str
    ip: str
    subnet: str
    layer: Literal["L2", "L3", "L4", "L7"]
    service: Optional[str]
    cve_id: Optional[str]
    # Zero-waste fields: static in Option B, mutated in Option A
    valid_from: float = field(default_factory=time.time)
    valid_to: Optional[float] = None
    observed_from: float = field(default_factory=time.time)
    observed_to: Optional[float] = None
    epistemic_state: Literal["CONFIRMED", "ASSUMED"] = "CONFIRMED"

# 3. Proposed Action from Planner/Execution (Diagrams 8, 9, 11)
@dataclass
class ProposedAction:
    step_id: int
    action_type: Literal["passive_recon", "active_scan", "exploit", "post_ex_read", "destructive"]
    target_ip: str
    cve_or_tool: str
    payload_cmd: str
    is_read_only: bool
    is_reversible: bool

# 4. Telemetry Log Row -> Directly feeds Diagram 10 (Reporting Engine)
@dataclass
class TelemetryEvent:
    run_id: str
    config: DeploymentConfig
    step_id: int
    proposed: ProposedAction
    in_roe_scope: bool
    gate_decision: Literal["AUTO_EXECUTE", "HITL_APPROVE", "HITL_REJECT", "DENY"]
    vm_verified: Optional[bool]
    exec_success: bool
    hallucinated_precondition: bool
    latency_ms: float