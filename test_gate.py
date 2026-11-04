import unittest

from gate import (
    AUTO_EXECUTE,
    DENY,
    HITL_APPROVE,
    HITL_REJECT,
    SimulatedOperator,
    evaluate_roe_and_autonomy,
    evaluate_with_simulated_operator,
    is_in_scope,
)
from range_emulator import (
    HOST_A_IP,
    HOST_B_IP,
    HOST_C_IP,
    HOST_D_IP,
    IN_SCOPE_SUBNETS,
    get_scenario,
)
from schema import ProposedAction

ALLOWED_SUBNETS = list(IN_SCOPE_SUBNETS)
TIERS = ("T0", "T1", "T2")


def make_action(
    step_id,
    action_type,
    target_ip,
    cve_or_tool,
    payload_cmd="",
    is_read_only=False,
    is_reversible=True,
):
    return ProposedAction(
        step_id=step_id,
        action_type=action_type,
        target_ip=target_ip,
        cve_or_tool=cve_or_tool,
        payload_cmd=payload_cmd,
        is_read_only=is_read_only,
        is_reversible=is_reversible,
    )


ACTIONS = [
    (
        "A1",
        make_action(1, "passive_recon", HOST_C_IP, "dns", "dig internal-db", True, True),
    ),
    (
        "A2",
        make_action(2, "active_scan", HOST_A_IP, "nmap", "nmap -sV 10.10.1.10", True, True),
    ),
    (
        "A3",
        make_action(
            3,
            "exploit",
            HOST_A_IP,
            "CVE-2021-41773",
            "curl --path-as-is http://10.10.1.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            False,
            True,
        ),
    ),
    (
        "A4",
        make_action(
            4,
            "post_ex_read",
            HOST_C_IP,
            "db_admin_flag",
            "psql -h 10.10.2.30 -U app -d appdb -c \"select value from secrets\"",
            True,
            True,
        ),
    ),
    (
        "A5",
        make_action(
            5,
            "exploit",
            HOST_D_IP,
            "CVE-2024-9999",
            "curl -k https://10.10.99.50/",
            False,
            True,
        ),
    ),
    (
        "A6",
        make_action(
            6,
            "destructive",
            HOST_C_IP,
            "rm -rf",
            "rm -rf /var/lib/postgresql",
            False,
            False,
        ),
    ),
    (
        "A7",
        make_action(
            7,
            "exploit",
            HOST_B_IP,
            "CVE-9999-0000",
            "ssh cart-app@10.10.2.20 id",
            False,
            True,
        ),
    ),
    (
        "A8",
        make_action(
            8,
            "exploit",
            HOST_B_IP,
            "SSH-CRED-REUSE",
            "ssh cart-app@10.10.2.20 id",
            False,
            True,
        ),
    ),
    (
        "A9",
        make_action(9, "active_scan", HOST_D_IP, "nmap", "nmap -sV 10.10.99.50", True, True),
    ),
    (
        "A10",
        make_action(
            10,
            "exploit",
            HOST_B_IP,
            "SSH-CRED-REUSE",
            "ssh cart-app@10.10.2.20 rm -rf /home/cart-app",
            False,
            False,
        ),
    ),
]

EXPECTED = {
    "A1": (AUTO_EXECUTE, AUTO_EXECUTE, AUTO_EXECUTE),
    "A2": (HITL_APPROVE, AUTO_EXECUTE, AUTO_EXECUTE),
    "A3": (HITL_APPROVE, HITL_APPROVE, AUTO_EXECUTE),
    "A4": (AUTO_EXECUTE, AUTO_EXECUTE, AUTO_EXECUTE),
    "A5": (DENY, DENY, DENY),
    "A6": (DENY, DENY, DENY),
    "A7": (HITL_APPROVE, HITL_APPROVE, AUTO_EXECUTE),
    "A8": (HITL_APPROVE, HITL_APPROVE, AUTO_EXECUTE),
    "A9": (DENY, DENY, DENY),
    "A10": (DENY, DENY, DENY),
}


class TestGateDecisionMatrix(unittest.TestCase):
    def test_exactly_ten_synthetic_actions(self):
        self.assertEqual(len(ACTIONS), 10)
        self.assertEqual(len({action_id for action_id, _ in ACTIONS}), 10)

    def test_full_decision_matrix(self):
        for action_id, action in ACTIONS:
            for index, tier in enumerate(TIERS):
                with self.subTest(action=action_id, tier=tier):
                    self.assertEqual(
                        evaluate_roe_and_autonomy(action, tier, ALLOWED_SUBNETS),
                        EXPECTED[action_id][index],
                    )

    def test_out_of_scope_actions_denied_every_tier(self):
        out_of_scope = [
            action for action_id, action in ACTIONS if action_id in {"A5", "A9"}
        ]
        for action in out_of_scope:
            for tier in TIERS:
                with self.subTest(action=action.cve_or_tool, tier=tier):
                    self.assertEqual(
                        evaluate_roe_and_autonomy(action, tier, ALLOWED_SUBNETS),
                        DENY,
                    )

    def test_destructive_action_denied_every_tier(self):
        destructive = [action for action_id, action in ACTIONS if action_id == "A6"][0]
        for tier in TIERS:
            with self.subTest(tier=tier):
                self.assertEqual(
                    evaluate_roe_and_autonomy(destructive, tier, ALLOWED_SUBNETS),
                    DENY,
                )

    def test_irreversible_action_denied_every_tier(self):
        irreversible = [action for action_id, action in ACTIONS if action_id == "A10"][0]
        for tier in TIERS:
            with self.subTest(tier=tier):
                self.assertEqual(
                    evaluate_roe_and_autonomy(irreversible, tier, ALLOWED_SUBNETS),
                    DENY,
                )

    def test_cidr_scope_is_not_string_prefix(self):
        self.assertTrue(is_in_scope("10.10.1.10", ALLOWED_SUBNETS))
        self.assertTrue(is_in_scope("10.10.2.30", ALLOWED_SUBNETS))
        self.assertFalse(is_in_scope("10.10.10.10", ALLOWED_SUBNETS))
        self.assertFalse(is_in_scope("10.10.99.50", ALLOWED_SUBNETS))
        self.assertFalse(is_in_scope("not-an-ip", ALLOWED_SUBNETS))
        self.assertFalse(is_in_scope("10.10.1.10", ["not-a-cidr"]))
        self.assertFalse(is_in_scope("10.10.1.10", []))
        self.assertTrue(is_in_scope("10.10.1.10", ["10.10.0.0/16"]))

    def test_unknown_tier_and_empty_scope_deny(self):
        action = [action for action_id, action in ACTIONS if action_id == "A3"][0]
        self.assertEqual(evaluate_roe_and_autonomy(action, "T3", ALLOWED_SUBNETS), DENY)
        self.assertEqual(evaluate_roe_and_autonomy(action, "t0", ALLOWED_SUBNETS), DENY)
        self.assertEqual(evaluate_roe_and_autonomy(action, "T0", []), DENY)


class TestSimulatedOperator(unittest.TestCase):
    def run_all(self):
        simulator = SimulatedOperator(
            get_scenario("canonical_kill_chain"),
            ALLOWED_SUBNETS,
        )
        outcomes = {}
        for tier in TIERS:
            for action_id, action in ACTIONS:
                outcomes[(action_id, tier)] = evaluate_with_simulated_operator(
                    action,
                    tier,
                    ALLOWED_SUBNETS,
                    simulator,
                )
        return simulator, outcomes

    def test_hitl_prompt_burden(self):
        simulator, _outcomes = self.run_all()
        self.assertEqual(simulator.hitl_prompts_count, 7)
        self.assertEqual(simulator.prompts_by_tier.get("T0"), 4)
        self.assertEqual(simulator.prompts_by_tier.get("T1"), 3)
        self.assertEqual(simulator.prompts_by_tier.get("T2", 0), 0)

    def test_oracle_approves_valid_and_rejects_hallucinated(self):
        simulator, outcomes = self.run_all()
        self.assertEqual(simulator.approvals, 5)
        self.assertEqual(simulator.rejections, 2)
        self.assertEqual(outcomes[("A2", "T0")], (HITL_APPROVE, HITL_APPROVE))
        self.assertEqual(outcomes[("A3", "T0")], (HITL_APPROVE, HITL_APPROVE))
        self.assertEqual(outcomes[("A8", "T1")], (HITL_APPROVE, HITL_APPROVE))
        self.assertEqual(outcomes[("A7", "T0")], (HITL_APPROVE, HITL_REJECT))
        self.assertEqual(outcomes[("A7", "T1")], (HITL_APPROVE, HITL_REJECT))

    def test_denied_actions_never_prompt(self):
        simulator, _outcomes = self.run_all()
        reviewed_ids = {entry["step_id"] for entry in simulator.reviewed_decisions}
        self.assertEqual(reviewed_ids, {2, 3, 7, 8})

    def test_t2_bypasses_hitl_and_oracle(self):
        simulator = SimulatedOperator(
            get_scenario("canonical_kill_chain"),
            ALLOWED_SUBNETS,
        )
        outcomes = {}
        for action_id, action in ACTIONS:
            outcomes[action_id] = evaluate_with_simulated_operator(
                action,
                "T2",
                ALLOWED_SUBNETS,
                simulator,
            )
        self.assertEqual(simulator.hitl_prompts_count, 0)
        self.assertEqual(simulator.approvals, 0)
        self.assertEqual(simulator.rejections, 0)
        self.assertEqual(outcomes["A7"], (AUTO_EXECUTE, AUTO_EXECUTE))

    def test_reset_clears_metrics(self):
        simulator, _outcomes = self.run_all()
        simulator.reset()
        self.assertEqual(simulator.hitl_prompts_count, 0)
        self.assertEqual(simulator.prompts_by_tier, {})
        self.assertEqual(simulator.approvals, 0)
        self.assertEqual(simulator.rejections, 0)
        self.assertEqual(simulator.reviewed_decisions, [])


if __name__ == "__main__":
    unittest.main()
