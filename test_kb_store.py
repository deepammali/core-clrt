import copy
import json
import tempfile
import unittest
from pathlib import Path

from kb_store import (
    BUNDLE_PATH,
    DEFAULT_SIGNING_KEY,
    DISTRACTOR_SOURCE,
    KBBundleError,
    PRETRAINING_GUESSES,
    PRETRAINING_SOURCE,
    build_bundle,
    compare_modes,
    load_signed_bundle,
    write_signed_bundle,
)
from range_emulator import (
    HOST_A_IP,
    HOST_B_IP,
    HOST_C_IP,
    get_scenario,
)


def bundle_payload():
    return json.loads(BUNDLE_PATH.read_text())


class TestSignedBundle(unittest.TestCase):
    def test_default_bundle_verifies(self):
        store = load_signed_bundle(mode="air-gapped")
        self.assertTrue(store.signature_verified)
        self.assertEqual(store.bundle_id, "cart-kb-2026-11-03")
        self.assertEqual(store.trust_threshold, 0.7)

    def test_wrong_key_rejected(self):
        with self.assertRaises(KBBundleError):
            load_signed_bundle(mode="air-gapped", signing_key="wrong-key")

    def test_tampered_trust_rejected(self):
        payload = bundle_payload()
        payload["cve_rules"][0]["trust"] = 0.99
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(payload))
            with self.assertRaises(KBBundleError):
                load_signed_bundle(path=path, mode="air-gapped")

    def test_tampered_distractor_rejected(self):
        payload = bundle_payload()
        payload["distractor_cves"][0]["trust"] = 0.8
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tampered.json"
            path.write_text(json.dumps(payload))
            with self.assertRaises(KBBundleError):
                load_signed_bundle(path=path, mode="air-gapped")

    def test_missing_signature_rejected(self):
        payload = bundle_payload()
        payload.pop("signature")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsigned.json"
            path.write_text(json.dumps(payload))
            with self.assertRaises(KBBundleError):
                load_signed_bundle(path=path, mode="air-gapped")

    def test_air_gapped_uncurated_is_invalid(self):
        with self.assertRaises(KBBundleError):
            load_signed_bundle(mode="air-gapped", uncurated=True)

    def test_invalid_mode_rejected(self):
        with self.assertRaises(KBBundleError):
            load_signed_bundle(mode="offline")


class TestBundleContents(unittest.TestCase):
    def test_exactly_twenty_distractors(self):
        payload = bundle_payload()
        distractors = payload["distractor_cves"]
        self.assertEqual(len(distractors), 20)
        self.assertEqual(len({entry["cve_id"] for entry in distractors}), 20)
        for entry in distractors:
            with self.subTest(cve=entry["cve_id"]):
                self.assertLess(entry["trust"], 0.7)
                self.assertFalse(entry["verified_poc"])
                self.assertEqual(entry["source"], DISTRACTOR_SOURCE)

    def test_all_trust_scores_in_range(self):
        payload = bundle_payload()
        for key in ("ttp_mappings", "cve_rules", "distractor_cves"):
            for entry in payload[key]:
                with self.subTest(collection=key, item=entry):
                    self.assertGreaterEqual(entry["trust"], 0.0)
                    self.assertLessEqual(entry["trust"], 1.0)

    def test_trusted_rules_map_to_range_services(self):
        scenario = get_scenario("canonical_kill_chain")
        store = load_signed_bundle(mode="air-gapped")
        host_a = scenario.hosts[HOST_A_IP]
        host_b = scenario.hosts[HOST_B_IP]
        host_c = scenario.hosts[HOST_C_IP]
        by_id = {entry.cve_id: entry for entry in store.trusted_cves}
        self.assertTrue(
            by_id["CVE-2021-41773"].matches_version(host_a.services[0].version)
        )
        self.assertTrue(
            by_id["SSH-CRED-REUSE"].matches_version(host_b.services[0].version)
        )
        self.assertTrue(
            by_id["DB-CRED-REUSE"].matches_version(host_c.services[0].version)
        )

    def test_matching_jenkins_distractor_is_low_trust(self):
        scenario = get_scenario("canonical_kill_chain")
        store = load_signed_bundle(mode="air-gapped")
        entry = next(
            item for item in store.filtered_cves if item.cve_id == "CVE-2024-23897"
        )
        self.assertLess(entry.trust, 0.7)
        self.assertTrue(
            entry.matches_version(scenario.hosts[HOST_B_IP].services[1].version)
        )
        self.assertNotIn(
            "CVE-2024-23897",
            [candidate.cve_id for candidate in store.candidate_cves],
        )


class TestTrustModes(unittest.TestCase):
    def test_air_gapped_keeps_only_trusted(self):
        store = load_signed_bundle(mode="air-gapped")
        self.assertEqual(store.mode, "air-gapped")
        self.assertEqual(len(store.candidate_cves), 3)
        self.assertEqual(len(store.filtered_cves), 20)
        self.assertEqual(store.excluded_low_trust_count, 20)
        self.assertTrue(all(entry.trust >= 0.7 for entry in store.candidate_cves))
        self.assertEqual(
            {entry.cve_id for entry in store.candidate_cves},
            {"CVE-2021-41773", "SSH-CRED-REUSE", "DB-CRED-REUSE"},
        )

    def test_uncurated_exposes_distractors_and_guesses(self):
        store = load_signed_bundle(mode="online", uncurated=True)
        self.assertEqual(store.mode, "online")
        self.assertEqual(len(store.candidate_cves), 28)
        self.assertEqual(len(store.pretraining_guesses), 5)
        self.assertEqual(store.excluded_low_trust_count, 0)
        ids = {entry.cve_id for entry in store.candidate_cves}
        self.assertIn("CVE-2024-23897", ids)
        self.assertIn("CVE-2022-22965", ids)
        self.assertEqual(
            sum(
                1
                for entry in store.candidate_cves
                if entry.source == DISTRACTOR_SOURCE
            ),
            20,
        )
        self.assertEqual(
            sum(
                1
                for entry in store.candidate_cves
                if entry.source == PRETRAINING_SOURCE
            ),
            5,
        )

    def test_threshold_boundary(self):
        payload = build_bundle()
        payload["trust_threshold"] = 0.7
        payload["cve_rules"] = [
            {
                "cve_id": "CVE-THRESHOLD-070",
                "service": "http",
                "version_regex": ".*",
                "asset_ip": HOST_A_IP,
                "trust": 0.7,
                "verified_poc": True,
                "source": "test",
                "description": "kept",
                "kind": "cve",
            },
            {
                "cve_id": "CVE-THRESHOLD-0699",
                "service": "http",
                "version_regex": ".*",
                "asset_ip": HOST_A_IP,
                "trust": 0.699,
                "verified_poc": True,
                "source": "test",
                "description": "filtered",
                "kind": "cve",
            },
        ]
        payload["distractor_cves"] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "threshold.json"
            write_signed_bundle(path=path, bundle=payload)
            store = load_signed_bundle(path=path, mode="air-gapped")
        ids = {entry.cve_id for entry in store.candidate_cves}
        self.assertIn("CVE-THRESHOLD-070", ids)
        self.assertNotIn("CVE-THRESHOLD-0699", ids)
        self.assertEqual(len(store.filtered_cves), 1)

    def test_planning_context_is_json_serializable(self):
        store = load_signed_bundle(mode="air-gapped")
        context = store.planning_context()
        encoded = json.dumps(context, sort_keys=True)
        self.assertIn("air-gapped", encoded)
        self.assertEqual(context["mode"], "air-gapped")
        self.assertEqual(context["excluded_low_trust_count"], 20)
        self.assertEqual(len(context["candidate_cves"]), 3)

    def test_uncurated_planning_context_has_no_exclusions(self):
        store = load_signed_bundle(mode="online", uncurated=True)
        context = store.planning_context()
        self.assertEqual(context["mode"], "online")
        self.assertEqual(context["excluded_low_trust_count"], 0)
        self.assertEqual(len(context["candidate_cves"]), 28)


class TestComparison(unittest.TestCase):
    def test_compare_modes_metrics(self):
        metrics = compare_modes()
        air = metrics["air_gapped"]
        online = metrics["uncurated"]
        delta = metrics["delta"]
        self.assertEqual(metrics["trust_threshold"], 0.7)
        self.assertEqual(air["candidate_count"], 3)
        self.assertEqual(air["filtered_low_trust"], 20)
        self.assertEqual(air["distractor_count"], 0)
        self.assertEqual(air["pretraining_guess_count"], 0)
        self.assertEqual(air["unverified_count"], 0)
        self.assertEqual(online["candidate_count"], 28)
        self.assertEqual(online["distractor_count"], 20)
        self.assertEqual(online["pretraining_guess_count"], 5)
        self.assertEqual(online["unverified_count"], 25)
        self.assertEqual(delta["candidates_exposed"], 25)
        self.assertEqual(delta["distractors_exposed"], 20)
        self.assertEqual(delta["pretraining_guesses_exposed"], 5)
        self.assertAlmostEqual(air["mean_trust"], 0.946667, places=6)
        self.assertAlmostEqual(online["mean_trust"], 0.448929, places=6)
        self.assertGreater(delta["mean_trust_drop"], 0.4)

    def test_compare_modes_does_not_mutate_sources(self):
        before = copy.deepcopy(PRETRAINING_GUESSES)
        for _ in range(2):
            compare_modes()
        self.assertEqual(before, PRETRAINING_GUESSES)
        self.assertEqual(DEFAULT_SIGNING_KEY, "cart-airgap-local-dev-key-2026")


if __name__ == "__main__":
    unittest.main()
