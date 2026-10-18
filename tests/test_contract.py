"""Synthetic contract checks; never a live connector or deployment test."""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

import weio_evidence_checks
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


    def assert_rejected(self, value, reason):
        for module in (connector, provenance):
            with self.subTest(server=module.SERVER_NAME, value=value):
                probe = module.fixture()
                probe["scope"] = [value]
                with self.assertRaises(module.Invalid) as cm:
                    module.run(probe)
                self.assertIn(reason, str(cm.exception))

    def test_leading_slash_rejected_by_format_rule(self):
        self.assert_rejected("/etc/passwd", "has invalid format")

    def test_drive_path_rejected(self):
        self.assert_rejected("C:/unsafe", "not a path or URL")

    def test_dotdot_segment_rejected(self):
        self.assert_rejected("logs/../secret", "not a path or URL")

    def test_url_rejected(self):
        self.assert_rejected("https://example.com/x", "not a path or URL")

    def test_relative_label_accepted_and_not_opened(self):
        for module in (connector, provenance):
            with self.subTest(server=module.SERVER_NAME):
                value = module.fixture()
                value["scope"] = ["logs/run1.log"]
                with mock.patch("builtins.open", side_effect=AssertionError("opened")), \
                     mock.patch("os.stat", side_effect=AssertionError("stat")):
                    result = module.run(value)
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["binding"]["scope_digest"], module.digest(["logs/run1.log"]))

    def test_url_like_label_without_scheme_separator_accepted(self):
        # documented: URL-like values without "://" pass and are opaque labels
        for module in (connector, provenance):
            with self.subTest(server=module.SERVER_NAME):
                value = module.fixture()
                value["scope"] = ["file:/etc/passwd"]
                with mock.patch("builtins.open", side_effect=AssertionError("opened")):
                    self.assertEqual(module.run(value)["status"], "PASS")

    def test_self_test_labels_match_probes(self):
        for module in (connector, provenance):
            with self.subTest(server=module.SERVER_NAME):
                checks = module.self_test()["checks"]
                for label, value, _reason in module.PATH_PROBES:
                    self.assertIn(value, label)
                    self.assertIn(label, checks)
                self.assertIn("relative label 'logs/run1.log' accepted as an opaque label; open() and os.stat() not called", checks)
                self.assertNotIn("filesystem path and URL inputs rejected", checks)


# The worked example in README.md, section "Check a result yourself".
DOCUMENTED_RECEIPTS = {
    "weio-connector-readiness": ("cr-d8dc0b654877026b06a91f33f1186902", "f1a2de9a518bf7fb00536c95e7aa335333d7f6d835eaf6570a7999c958a8043f"),
    "weio-production-provenance": ("pp-a6d19670045d3209bbb9fcbffc65055b", "e2ba725e55387c8c80be09116724c62c4421daa57e491657a24fe6b9869e6b60"),
}


def recompute(arguments, result, prefix):
    """The documented outsider method: plain SHA-256 over canonical JSON, no package code."""
    canon = lambda v: json.dumps(v, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    body = {k: v for k, v in result.items() if k not in ("ok", "consistency_check_passed", "approval_granted", "receipt_id")}
    return prefix + hashlib.sha256(canon(body)).hexdigest()[:32], hashlib.sha256(canon(arguments)).hexdigest()


class ReceiptRecomputeTests(unittest.TestCase):
    def test_worked_example_recomputes(self):
        for module, prefix in ((connector, "cr-"), (provenance, "pp-")):
            with self.subTest(server=module.SERVER_NAME):
                arguments = module.fixture()
                reply = module.process({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": module.TOOL["name"], "arguments": json.loads(json.dumps(arguments))}})
                result = json.loads(reply["result"]["content"][0]["text"])
                receipt_id, input_digest = recompute(arguments, result, prefix)
                self.assertEqual(receipt_id, result["receipt_id"])
                self.assertEqual(input_digest, result["binding"]["input_digest"])
                self.assertEqual((receipt_id, input_digest), DOCUMENTED_RECEIPTS[module.SERVER_NAME])

    def test_changed_input_changes_receipt(self):
        value = provenance.fixture()
        value["observations"]["public"]["artifact_digest"] = "b" * 64
        result = provenance.run(value)
        self.assertNotEqual(recompute(value, result, "pp-")[0], DOCUMENTED_RECEIPTS["weio-production-provenance"][0])
        self.assertEqual(recompute(value, result, "pp-")[0], result["receipt_id"])

    def test_receipt_is_an_unsigned_consistency_hash(self):
        """README: receipt_id is an unsigned consistency hash: anyone can compute one for any result, so a match shows only
        that the hashed fields (including binding.input_digest) are consistent with each other, not who produced the result
        or that it is correct. Here an edited result (status flipped) gets a receipt_id that recomputes, and its input_digest
        still matches the inputs."""
        for module, prefix in ((connector, "cr-"), (provenance, "pp-")):
            with self.subTest(server=module.SERVER_NAME):
                arguments = module.fixture()
                forged = copy.deepcopy(module.run(arguments))
                forged["status"] = "FAIL" if forged["status"] != "FAIL" else "PASS"
                forged["receipt_id"] = recompute(arguments, forged, prefix)[0]
                self.assertNotEqual(forged["receipt_id"], module.run(arguments)["receipt_id"])
                self.assertEqual(recompute(arguments, forged, prefix)[0], forged["receipt_id"])
                self.assertEqual(recompute(arguments, forged, prefix)[1], forged["binding"]["input_digest"])

    def test_readme_cites_the_tested_values(self):
        readme = os.path.join(os.path.dirname(__file__), "..", "README.md")
        if not os.path.exists(readme):
            self.skipTest("README.md not beside tests/")
        with open(readme, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(DOCUMENTED_RECEIPTS["weio-production-provenance"][0], text)


INIT_REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
REPO_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class VersionHygieneTests(unittest.TestCase):
    def test_initialize_reports_package_version(self):
        for module in (connector, provenance):
            with self.subTest(module=module.__name__):
                reply = module.process(copy.deepcopy(INIT_REQUEST))
                self.assertEqual(reply["result"]["serverInfo"]["version"], weio_evidence_checks.__version__)

    def test_package_version_matches_pyproject(self):
        with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as fh:
            declared = tomllib.load(fh)["project"]["version"]
        self.assertEqual(weio_evidence_checks.__version__, declared)

    def test_receipt_body_version_is_contract_version(self):
        for module in (connector, provenance):
            with self.subTest(module=module.__name__):
                self.assertEqual(module.RECEIPT_VERSION, "0.1.0")
                self.assertEqual(module.run(module.fixture())["version"], "0.1.0")

    def test_no_built_artifacts_tracked(self):
        if not os.path.isdir(os.path.join(REPO_ROOT, ".git")):
            self.skipTest("not a git checkout")
        listed = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        self.assertEqual([name for name in listed if name.endswith((".whl", ".tar.gz"))], [])

    def test_mcpb_layout_single_file_reports_version(self):
        for module in (connector, provenance):
            name = module.__name__.rsplit(".", 1)[-1]
            with self.subTest(module=name), tempfile.TemporaryDirectory() as tmp:
                os.makedirs(os.path.join(tmp, "server"))
                script = os.path.join(tmp, "server", name + ".py")
                shutil.copy(module.__file__, script)
                done = subprocess.run([sys.executable, "-I", script], input=json.dumps(INIT_REQUEST) + "\n", cwd=tmp, capture_output=True, text=True, timeout=15)
                self.assertNotIn("Traceback", done.stderr)
                lines = done.stdout.splitlines()
                self.assertEqual(len(lines), 1)
                self.assertEqual(json.loads(lines[0])["result"]["serverInfo"]["version"], weio_evidence_checks.__version__)


SECRET_CORPUS = {
    "bearer": "Bearer " + "A" * 20,
    "api_key": "api_key=" + "B" * 12,
    "token": "sk-" + "C" * 16,
    "ghp": "ghp_" + "D" * 16,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----",
    "jwt": "eyJ" + "E" * 10 + "." + "F" * 10 + "." + "G" * 10,
}


class SharedSecretRulesTests(unittest.TestCase):
    def test_secret_patterns_identical(self):
        self.assertEqual([p.pattern for p in connector.SECRET_PATTERNS], [p.pattern for p in provenance.SECRET_PATTERNS])

    def test_shared_rejection_corpus(self):
        for module in (connector, provenance):
            for name, secret in SECRET_CORPUS.items():
                for field in ("idempotency_key", "scope"):
                    with self.subTest(server=module.SERVER_NAME, value=name, field=field):
                        arguments = module.fixture()
                        if field == "scope":
                            arguments["scope"][0] = secret
                        else:
                            arguments[field] = secret
                        reply = module.process({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": module.TOOL["name"], "arguments": arguments}})
                        self.assertTrue("error" in reply or reply["result"].get("isError") is True, reply)
                        self.assertNotIn(secret, json.dumps(reply))


class StrictStdinTests(unittest.TestCase):
    def test_invalid_byte_does_not_stop_server_mcpb_layout(self):
        ping = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode() + b"\n"
        for module in (connector, provenance):
            name = module.__name__.rsplit(".", 1)[-1]
            with self.subTest(module=name), tempfile.TemporaryDirectory() as tmp:
                os.makedirs(os.path.join(tmp, "server"))
                script = os.path.join(tmp, "server", name + ".py")
                shutil.copy(module.__file__, script)
                env = dict(os.environ, PYTHONIOENCODING="utf-8:strict")
                done = subprocess.run([sys.executable, "-s", script], input=b"\xff\n" + ping, cwd=tmp, env=env, capture_output=True, timeout=15)
                self.assertNotIn(b"Traceback", done.stderr)
                self.assertEqual(done.returncode, 0, done.stderr)
                lines = [json.loads(line) for line in done.stdout.decode("utf-8").splitlines()]
                self.assertEqual(len(lines), 2, lines)
                self.assertEqual(lines[0]["error"]["code"], -32700)
                self.assertIsNone(lines[0]["id"])
                self.assertEqual(lines[1]["id"], 7)
                self.assertIn("result", lines[1])


if __name__ == "__main__":
    unittest.main()
