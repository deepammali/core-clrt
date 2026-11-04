import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from range_emulator import Scenario
from schema import ProposedAction

AUTO_EXECUTE = "AUTO_EXECUTE"
HITL_APPROVE = "HITL_APPROVE"
HITL_REJECT = "HITL_REJECT"
DENY = "DENY"


def _networks(allowed_subnets: List[str]) -> Tuple[Any, ...]:
    parsed = []
    for subnet in allowed_subnets:
        try:
            parsed.append(ipaddress.ip_network(subnet, strict=False))
        except (TypeError, ValueError):
            continue
    return tuple(parsed)


def is_in_scope(target_ip: str, allowed_subnets: List[str]) -> bool:
    try:
        address = ipaddress.ip_address(target_ip)
    except (TypeError, ValueError):
        return False
    for network in _networks(allowed_subnets):
        try:
            if address in network:
                return True
        except TypeError:
            continue
    return False


def evaluate_roe_and_autonomy(
    action: ProposedAction,
    tier: str,
    allowed_subnets: List[str],
) -> str:
    in_scope = is_in_scope(action.target_ip, allowed_subnets)

    if not in_scope or not action.is_reversible or action.action_type == "destructive":
        return DENY

    if tier == "T0":
        if action.action_type in {"passive_recon", "post_ex_read"}:
            return AUTO_EXECUTE
        return HITL_APPROVE

    if tier == "T1":
        if action.is_read_only:
            return AUTO_EXECUTE
        return HITL_APPROVE

    if tier == "T2":
        return AUTO_EXECUTE

    return DENY


@dataclass
class SimulatedOperator:
    scenario: Scenario
    allowed_subnets: List[str]
    hitl_prompts_count: int = 0
    prompts_by_tier: Dict[str, int] = field(default_factory=dict)
    approvals: int = 0
    rejections: int = 0
    reviewed_decisions: List[Dict[str, Any]] = field(default_factory=list)

    def reset(self) -> None:
        self.hitl_prompts_count = 0
        self.prompts_by_tier = {}
        self.approvals = 0
        self.rejections = 0
        self.reviewed_decisions = []

    def _oracle_approves(self, action: ProposedAction) -> bool:
        if not is_in_scope(action.target_ip, self.allowed_subnets):
            return False
        if action.action_type == "destructive" or not action.is_reversible:
            return False
        host = self.scenario.hosts.get(action.target_ip)
        if action.action_type == "exploit":
            if host is None:
                return False
            return action.cve_or_tool in host.vulnerabilities
        if action.action_type == "post_ex_read":
            return host is not None
        if action.action_type in {"active_scan", "passive_recon"}:
            return True
        return False

    def review(self, action: ProposedAction, gate_decision: str, tier: str) -> str:
        if gate_decision != HITL_APPROVE:
            return gate_decision

        self.hitl_prompts_count += 1
        self.prompts_by_tier[tier] = self.prompts_by_tier.get(tier, 0) + 1
        approved = self._oracle_approves(action)
        final_decision = HITL_APPROVE if approved else HITL_REJECT
        if approved:
            self.approvals += 1
        else:
            self.rejections += 1
        self.reviewed_decisions.append(
            {
                "step_id": action.step_id,
                "tier": tier,
                "target_ip": action.target_ip,
                "action_type": action.action_type,
                "cve_or_tool": action.cve_or_tool,
                "gate_decision": gate_decision,
                "final_decision": final_decision,
                "oracle_approved": approved,
            }
        )
        return final_decision


def evaluate_with_simulated_operator(
    action: ProposedAction,
    tier: str,
    allowed_subnets: List[str],
    simulator: SimulatedOperator,
) -> Tuple[str, str]:
    gate_decision = evaluate_roe_and_autonomy(action, tier, allowed_subnets)
    final_decision = simulator.review(action, gate_decision, tier)
    return gate_decision, final_decision
