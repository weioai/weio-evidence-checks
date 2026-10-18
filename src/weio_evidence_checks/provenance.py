#!/usr/bin/env python3
"""Deterministic, read-only release provenance MCP gate."""
from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import sys
from typing import Any

SERVER_NAME = "weio-production-provenance"
SERVER_VERSION = "0.1.0"
PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26")
MAX_LINE = 256_000
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
WQ_ID = r"^WQ-[1-9][0-9]{0,11}$"
SHA256 = r"^[a-f0-9]{64}$"
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password)\s*[:=]"),
    re.compile(r"\b(?:sk|ghp|xox[baprs])[-_][A-Za-z0-9_-]{10,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def obj(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


SAFE = {"type": "string", "minLength": 1, "maxLength": 128, "pattern": SAFE_ID}
DIGEST = {"type": "string", "pattern": SHA256}
EXPECTED = obj({
    "source_revision": SAFE, "artifact_digest": DIGEST,
    "source_identifier": SAFE, "build_identifier": SAFE,
    "deployment_identifier": SAFE, "public_identifier": SAFE,
}, ["source_revision", "artifact_digest", "source_identifier", "build_identifier", "deployment_identifier", "public_identifier"])
OBSERVATION = obj({
    "state": {"type": "string", "enum": ["observed", "unknown"]},
    "identifier": SAFE, "source_revision": SAFE, "artifact_digest": DIGEST,
}, ["state"])
INPUT_SCHEMA = obj({
    "work_queue_id": {"type": "string", "pattern": WQ_ID}, "revision": SAFE,
    "scope": {"type": "array", "items": SAFE, "minItems": 1, "maxItems": 64},
    "idempotency_key": SAFE, "expected": EXPECTED,
    "observations": obj({name: OBSERVATION for name in ("source", "build", "deployment", "public")}, ["source", "build", "deployment", "public"]),
}, ["work_queue_id", "revision", "scope", "idempotency_key", "expected", "observations"])
INPUT_SCHEMA["description"] = (
    "Closed-world schema for caller-supplied expected and observed values. The comparison "
    "does not perform live observation, independent proof, authenticity verification, or approval."
)

ASSURANCE_SCOPE = {
    "mode": "closed_world_caller_supplied_consistency",
    "live_probe_performed": False,
    "independent_evidence_obtained": False,
    "evidence_authenticity_verified": False,
    "approval_authority": False,
}
REMAINING_LIVE_REQUIREMENTS = [
    "independently_resolve_and_verify_the_source_revision",
    "independently_verify_build_artifact_digest_and_signature",
    "independently_observe_the_live_deployment_identifier",
    "independently_observe_the_publicly_served_revision_and_artifact",
    "obtain_separate_accountable_production_approval",
]


class Invalid(ValueError): pass


def validate(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    expected = schema.get("type")
    matches = {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str), "boolean": isinstance(value, bool), "integer": isinstance(value, int) and not isinstance(value, bool), "number": isinstance(value, (int, float)) and not isinstance(value, bool)}
    if expected and not matches.get(expected, False): raise Invalid(f"{path} must be {expected}")
    if "enum" in schema and value not in schema["enum"]: raise Invalid(f"{path} has invalid value")
    if isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 10**9): raise Invalid(f"{path} has invalid length")
        if schema.get("pattern") and not re.fullmatch(schema["pattern"], value): raise Invalid(f"{path} has invalid format")
        if any(pattern.search(value) for pattern in SECRET_PATTERNS): raise Invalid(f"{path} appears to contain a secret")
        normalized = value.replace("\\", "/")
        if re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("/") or "://" in normalized or ".." in normalized.split("/"): raise Invalid(f"{path} must be a logical identifier, not a path or URL")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and not math.isfinite(float(value)): raise Invalid(f"{path} must be finite")
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 10**9): raise Invalid(f"{path} has invalid item count")
        for index, item in enumerate(value): validate(item, schema["items"], f"{path}[{index}]")
    if isinstance(value, dict):
        props = schema.get("properties", {}); missing = [key for key in schema.get("required", []) if key not in value]; extra = sorted(set(value) - set(props)) if schema.get("additionalProperties") is False else []
        if missing or extra: raise Invalid(f"{path} missing={missing} unsupported_count={len(extra)}")
        for key, item in value.items(): validate(item, props[key], f"{path}.{key}")


def canonical(value: Any) -> str: return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
def digest(value: Any) -> str: return hashlib.sha256(canonical(value).encode()).hexdigest()


def run(arguments: dict[str, Any]) -> dict[str, Any]:
    validate(arguments, INPUT_SCHEMA)
    expected = arguments["expected"]
    if arguments["revision"] != expected["source_revision"]: raise Invalid("revision must equal expected.source_revision")
    layers: dict[str, Any] = {}; any_unknown = False; any_mismatch = False
    for layer in ("source", "build", "deployment", "public"):
        observed = arguments["observations"][layer]
        if observed["state"] == "unknown":
            if set(observed) != {"state"}: raise Invalid(f"unknown {layer} must not carry unverified values")
            layers[layer] = {"status": "UNKNOWN", "mismatches": ["not_observed"]}; any_unknown = True; continue
        required = {"state", "identifier", "source_revision", "artifact_digest"}
        if set(observed) != required: raise Invalid(f"observed {layer} requires identifier, source_revision, and artifact_digest")
        mismatches = []
        if observed["identifier"] != expected[f"{layer}_identifier"]: mismatches.append("identifier")
        if observed["source_revision"] != expected["source_revision"]: mismatches.append("source_revision")
        if observed["artifact_digest"] != expected["artifact_digest"]: mismatches.append("artifact_digest")
        layers[layer] = {"status": "FAIL" if mismatches else "PASS", "mismatches": mismatches}; any_mismatch |= bool(mismatches)
    status = "FAIL" if any_mismatch else ("UNKNOWN" if any_unknown else "PASS")
    binding = {"work_queue_id": arguments["work_queue_id"], "revision": arguments["revision"], "work_queue_digest": digest(arguments["work_queue_id"]), "revision_digest": digest(arguments["revision"]), "scope_digest": digest(sorted(set(arguments["scope"]))), "idempotency_key": arguments["idempotency_key"], "idempotency_digest": digest(arguments["idempotency_key"]), "input_digest": digest(arguments)}
    body = {
        "plugin": SERVER_NAME,
        "version": SERVER_VERSION,
        "binding": binding,
        "status": status,
        "layers": layers,
        "assurance_scope": dict(ASSURANCE_SCOPE),
        "remaining_live_requirements": list(REMAINING_LIVE_REQUIREMENTS),
        "limits": {"max_message_bytes": MAX_LINE, "max_scopes": 64, "layer_count": 4},
    }
    return {
        "ok": status == "PASS",
        **body,
        "consistency_check_passed": status == "PASS",
        "approval_granted": False,
        "receipt_id": "pp-" + digest(body)[:32],
    }


TOOL = {"name": "verify_production_provenance", "description": "Closed-world consistency comparison of caller-supplied release identifiers and digests. PASS is not live observation, independent proof, authenticity verification, or production approval.", "inputSchema": INPUT_SCHEMA, "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}}


def error(identifier: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    value = {"code": code, "message": message}
    if data is not None: value["data"] = data
    return {"jsonrpc": "2.0", "id": identifier, "error": value}


def process(message: Any) -> dict[str, Any] | None:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str): return error(message.get("id") if isinstance(message, dict) else None, -32600, "Invalid Request")
    if "id" not in message: return None
    identifier, method, params = message["id"], message["method"], message.get("params", {})
    if not isinstance(params, dict): return error(identifier, -32602, "Invalid params")
    if method == "initialize":
        protocol = params.get("protocolVersion")
        if protocol not in PROTOCOLS: return error(identifier, -32602, "Unsupported protocol version")
        return {"jsonrpc": "2.0", "id": identifier, "result": {"protocolVersion": protocol, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}, "instructions": "Closed-world caller-supplied consistency only; never treat PASS as live, independent, authentic, or approved."}}
    if method == "ping": return {"jsonrpc": "2.0", "id": identifier, "result": {}}
    if method == "tools/list": return {"jsonrpc": "2.0", "id": identifier, "result": {"tools": [TOOL]}}
    if method == "tools/call":
        if set(params) - {"name", "arguments", "_meta"} or params.get("name") != TOOL["name"]: return error(identifier, -32602, "Invalid params")
        try: payload = run(params.get("arguments", {}))
        except Invalid as exc: return {"jsonrpc": "2.0", "id": identifier, "result": {"content": [{"type": "text", "text": f"Invalid arguments: {exc}. Correct the arguments to match the tool inputSchema and description, then call again."}], "isError": True}}
        return {"jsonrpc": "2.0", "id": identifier, "result": {"content": [{"type": "text", "text": canonical(payload)}], "structuredContent": payload, "isError": not payload["ok"]}}
    return error(identifier, -32601, "Method not found")


def loads(raw: str) -> Any:
    if len(raw.encode()) > MAX_LINE: raise Invalid("message too large")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result: raise Invalid("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(Invalid(f"invalid constant {value}")))


def serve() -> int:
    for raw in sys.stdin:
        if not raw.strip(): continue
        try: response = process(loads(raw))
        except (Invalid, json.JSONDecodeError): response = error(None, -32700, "Parse error")
        except Exception: response = error(None, -32603, "Internal error")
        if response is not None: print(canonical(response), flush=True)
    return 0


def fixture() -> dict[str, Any]:
    revision, artifact = "rev-deadbeef", "a" * 64
    expected = {"source_revision": revision, "artifact_digest": artifact, "source_identifier": "src-1", "build_identifier": "build-1", "deployment_identifier": "deploy-1", "public_identifier": "public-1"}
    observations = {layer: {"state": "observed", "identifier": expected[f"{layer}_identifier"], "source_revision": revision, "artifact_digest": artifact} for layer in ("source", "build", "deployment", "public")}
    return {"work_queue_id": "WQ-202", "revision": revision, "scope": ["release:mail"], "idempotency_key": "WQ-202-rev-deadbeef", "expected": expected, "observations": observations}


def stdio_health(arguments: dict[str, Any]) -> None:
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": TOOL["name"], "arguments": arguments}},
    ]
    completed = subprocess.run([sys.executable, __file__], input="\n".join(canonical(item) for item in messages) + "\n", text=True, capture_output=True, timeout=10, check=True)
    replies = [json.loads(line) for line in completed.stdout.splitlines()]
    assert len(replies) == 3 and replies[0]["result"]["protocolVersion"] == "2025-06-18"
    assert replies[1]["result"]["tools"][0]["name"] == TOOL["name"] and not replies[2]["result"]["isError"]


# Self-test probes for the path rule in validate(): (check label, scope value, expected text of the Invalid message).
# A leading "/" already fails the SAFE_ID format rule (first character must be a letter or digit), before the path rule.
PATH_PROBES = (
    ("absolute path '/etc/passwd' rejected (format rule: must start with a letter or digit)", "/etc/passwd", "has invalid format"),
    ("Windows drive path 'C:/unsafe' rejected (path rule)", "C:/unsafe", "not a path or URL"),
    ("'..' segment 'logs/../secret' rejected (path rule)", "logs/../secret", "not a path or URL"),
    ("'://' URL 'https://example.com/x' rejected (path rule)", "https://example.com/x", "not a path or URL"),
)


def self_test() -> dict[str, Any]:
    checks = []; first, second = run(fixture()), run(fixture())
    assert first["ok"] and first["receipt_id"] == second["receipt_id"]; checks.append("PASS and deterministic receipt")
    assert first["consistency_check_passed"] and not first["approval_granted"]
    assert first["assurance_scope"] == ASSURANCE_SCOPE and first["remaining_live_requirements"]
    assert "production_approved" not in first
    checks.append("perfect caller input cannot overclaim live assurance or approval")
    mismatch = fixture(); mismatch["observations"]["public"]["artifact_digest"] = "b" * 64; result = run(mismatch); assert result["status"] == "FAIL" and not result["approval_granted"]; checks.append("digest mismatch fails closed")
    unknown = fixture(); unknown["observations"]["deployment"] = {"state": "unknown"}; assert run(unknown)["status"] == "UNKNOWN"; checks.append("unknown observation fails closed")
    invalid_unknown = fixture(); invalid_unknown["observations"]["deployment"]["state"] = "unknown"
    try: run(invalid_unknown); raise AssertionError("unknown carried values")
    except Invalid: checks.append("unknown values cannot masquerade as evidence")
    assert process({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})["result"]["protocolVersion"] == "2025-06-18"
    assert len(process({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]) == 1
    call = process({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": TOOL["name"], "arguments": fixture()}}); assert not call["result"]["isError"]; checks.append("MCP initialize, list, call")
    for label, value, reason in PATH_PROBES:
        probe = fixture(); probe["scope"] = [value]
        try: run(probe); raise AssertionError(value + " accepted")
        except Invalid as exc: assert reason in str(exc), str(exc)
        checks.append(label)
    from unittest import mock
    opaque = fixture(); opaque["scope"] = ["logs/run1.log"]
    with mock.patch("builtins.open", side_effect=AssertionError("label opened")), mock.patch("os.stat", side_effect=AssertionError("label opened")):
        assert run(opaque)["status"] == "PASS"
    checks.append("relative label 'logs/run1.log' accepted as an opaque label; open() and os.stat() not called")
    stdio_health(fixture()); checks.append("stdio MCP process health")
    return {"ok": True, "checks": checks, "pass_count": len(checks), "tool_count": 1}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test": print(json.dumps(self_test(), indent=2, sort_keys=True)); raise SystemExit(0)
    raise SystemExit(serve())
