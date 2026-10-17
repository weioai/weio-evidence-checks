"""Synthetic contract checks; never a live connector or deployment test."""
import copy
import json
import unittest

from weio_evidence_checks import connector, provenance


class ContractTests(unittest.TestCase):
    def test_connector_truthful_pass(self):
        result = connector.run(connector.fixture())
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["approval_granted"])
        self.assertFalse(result["assurance_scope"]["live_probe_performed"])
        self.assertEqual(result, connector.run(connector.fixture()))

    def test_connector_unknown_is_not_success(self):
        value = connector.fixture()
        del value["evidence"]["revocation"]
        result = connector.run(value)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["ok"])

    def test_connector_unapproved_scope_fails(self):
        value = connector.fixture()
        value["evidence"]["scopes"]["requested"].append("extra:write")
        self.assertEqual(connector.run(value)["status"], "FAIL")

    def test_connector_false_callback_fails(self):
        value = connector.fixture()
        value["evidence"]["callback"]["state_verified"] = False
        self.assertEqual(connector.run(value)["status"], "FAIL")

    def test_provenance_truthful_pass(self):
        result = provenance.run(provenance.fixture())
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["approval_granted"])
        self.assertFalse(result["assurance_scope"]["evidence_authenticity_verified"])
        self.assertEqual(result, provenance.run(provenance.fixture()))

    def test_provenance_mismatch_fails(self):
        value = provenance.fixture()
        value["observations"]["public"]["artifact_digest"] = "b" * 64
        result = provenance.run(value)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("artifact_digest", result["layers"]["public"]["mismatches"])

    def test_provenance_unknown_is_not_success(self):
        value = provenance.fixture()
        value["observations"]["deployment"] = {"state": "unknown"}
        self.assertEqual(provenance.run(value)["status"], "UNKNOWN")

    def test_unknown_cannot_keep_claimed_values(self):
        value = provenance.fixture()
        value["observations"]["public"]["state"] = "unknown"
        with self.assertRaises(provenance.Invalid):
            provenance.run(value)

    def test_both_reject_paths_and_duplicate_keys(self):
        for module in (connector, provenance):
            with self.subTest(server=module.SERVER_NAME):
                value = module.fixture()
                value["scope"] = ["C:/private/customer-data"]
                with self.assertRaises(module.Invalid):
                    module.run(value)
                with self.assertRaises(module.Invalid):
                    module.loads('{"id":1,"id":2}')

    def test_stdio_contract_messages(self):
        for module in (connector, provenance):
            with self.subTest(server=module.SERVER_NAME):
                response = module.process({"jsonrpc": "2.0", "id": 1,
                    "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
                self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")
                response = module.process({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                self.assertEqual(len(response["result"]["tools"]), 1)
                response = module.process({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": module.TOOL["name"], "arguments": module.fixture()}})
                self.assertFalse(response["result"]["isError"])
                self.assertFalse(response["result"]["structuredContent"]["approval_granted"])


if __name__ == "__main__":
    unittest.main()
