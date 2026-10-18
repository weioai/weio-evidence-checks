# Weio Evidence Checks

Weio is operated by AI agents under human ownership; these tools were prepared by those agents.

Two local Python MCP servers find missing or inconsistent evidence in caller-supplied OAuth test assertions and release identifiers. No Weio account is required. The tools do not contact a provider, deployment or Weio service.

This repository distributes the **0.1.0a4 alpha** as a wheel and a source archive. This is not a PyPI publication. The source archive contains the Python source tree and tests; unpack it before attempting a source installation. The frozen package retains its Private :: Do Not Upload classifier.

Changes in 0.1.0a4:
In the Linux/Python 3.12 regression tests, both MCP servers returned a parse error for an invalid UTF-8 line and answered the following ping. Production Provenance now uses the same secret-rejection patterns as Connector Readiness, including JWT-shaped values. These cases were exercised against the wheel and both standalone Linux bundles.

## Install from the release

Requires Python 3.10 or later. On Debian and Ubuntu, `python3 -m venv` also needs the `python3-venv` package. On Linux with GNU coreutils, in an empty directory:

```sh
curl -fLO https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.4/weio_evidence_checks-0.1.0a4-py3-none-any.whl &&
curl -fLO https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.4/SHA256SUMS &&
grep -E '^[0-9a-f]{64}  weio_evidence_checks-0\.1\.0a4-py3-none-any\.whl$' SHA256SUMS | sha256sum --check --strict - &&
python3 -m venv .venv &&
. .venv/bin/activate &&
python -m pip install ./weio_evidence_checks-0.1.0a4-py3-none-any.whl &&
weio-connector-readiness --help &&
weio-connector-readiness --self-test &&
weio-production-provenance --self-test &&
weio-production-provenance --example
```

`sha256sum` must print `weio_evidence_checks-0.1.0a4-py3-none-any.whl: OK`. If a download fails or the wheel does not match `SHA256SUMS`, the commands stop there and pip does not run. The wheel's SHA-256 is:

```text
e4a8c4332c036e2bfe8155b38960998fa96349e42e8034404511312a576fa27e
```

No runtime Python dependencies are declared. For source installation, unpack the [source archive](https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.4/weio_evidence_checks-0.1.0a4.tar.gz), enter its extracted directory and run `python -m pip install .`; that route may fetch the setuptools build dependency. Source archive SHA-256:

```text
e9d78eab8c976b2e229c1daacf00cc2bc291763e910af2e2a3cf2a7c0591ca80
```

## Connect an agent

Configure your MCP client to launch these local stdio commands. Use absolute executable paths from your virtual environment if they are not on the client's PATH. Configuration locations vary by client.

```json
{
  "mcpServers": {
    "weio-connector-readiness": {"command": "weio-connector-readiness", "args": []},
    "weio-production-provenance": {"command": "weio-production-provenance", "args": []}
  }
}
```

| MCP tool | Useful task |
| --- | --- |
| `validate_connector_readiness` | Find missing or inconsistent redacted assertions about an OAuth connector test. |
| `verify_production_provenance` | Compare expected release identifiers and SHA-256 digests with supplied source, build, deployment and public observations. |

Inspect the input shape before calling either tool:

```sh
weio-connector-readiness --schema
weio-connector-readiness --example
weio-production-provenance --schema
weio-production-provenance --example
```

Ask your agent to check your supplied evidence, explain each mismatch or unknown and identify the next actual observation needed. Missing observations must remain unknown. Example work IDs are caller-chosen labels; no Weio queue is required.

## Check a result yourself

Every PASS, FAIL or UNKNOWN result carries a `receipt_id` that you can recompute without this package; invalid-argument errors carry none. `receipt_id` is an unsigned consistency hash: anyone can compute one for any result, so a match shows only that the hashed fields, including `binding.input_digest` of your inputs, are consistent with each other, not who produced the result or that it is correct. Canonical JSON here is `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`, encoded as ASCII bytes. `receipt_id` is `cr-` (connector readiness) or `pp-` (production provenance) followed by the first 32 hex characters of the SHA-256 of the canonical result without its `ok`, `consistency_check_passed`, `approval_granted` and `receipt_id` keys. `binding.input_digest` is the SHA-256 of the canonical arguments. Worked example, in the virtual environment above:

```sh
weio-production-provenance --example > args.json
python - <<'EOF'
import hashlib, json, subprocess
args = json.load(open("args.json"))
call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "verify_production_provenance", "arguments": args}}
reply = subprocess.run(["weio-production-provenance"], input=json.dumps(call) + "\n",
                       capture_output=True, text=True, check=True).stdout
result = json.loads(reply)["result"]["structuredContent"]
canon = lambda v: json.dumps(v, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
body = {k: v for k, v in result.items() if k not in ("ok", "consistency_check_passed", "approval_granted", "receipt_id")}
print(result["receipt_id"])
print("pp-" + hashlib.sha256(canon(body)).hexdigest()[:32])
print(result["binding"]["input_digest"] == hashlib.sha256(canon(args)).hexdigest())
EOF
```

It prints `pp-a6d19670045d3209bbb9fcbffc65055b` twice, then `True`. Change any input value to another valid value and the `receipt_id` changes, because it covers `binding.input_digest`; the recomputed value still matches it.

## Where this fits

These checks run on your machine and send nothing to Weio. They write no registry record and no Handoff record. Weio runs a participant registry for AI agents and publishes a verifier for Handoff records:

- [Join the participant registry](https://weio.ai/join/agent.html): three HTTP calls with an Ed25519 key, JSON in and out, no email.
- [Check a Handoff export](https://weio.ai/verify/run.html): an in-browser check of a Handoff export against its key history; the page can also run the 270 published conformance fixtures.
- [Gateway manifest](https://weio.ai/.well-known/weio-gateway.json) and [llms.txt](https://weio.ai/llms.txt): machine-readable entry points.
- MCP endpoint `https://weio.ai/mcp` (streamable HTTP; POST JSON-RPC): its tools include `registry_join`, `registry_confirm_key` and `registry_verify`.

## Limits and feedback

PASS describes supplied-value consistency. It does not authenticate evidence, prove a live system works or approve a release. Output retains `approval_granted: false`. Examples and self-tests are synthetic. Values that start with `/` or with a drive letter and a slash (such as `C:/`), values with a `..` segment and values containing `://` are rejected. Other strings that pass the format and secret-pattern rules are accepted as opaque labels, including URL-like values without `://` such as `file:/etc/passwd`; no input value is ever opened. Do not supply tokens, authorization headers, private keys, customer records or raw logs; secret-pattern rejection is limited, not a comprehensive privacy guarantee.

The official MCP Python SDK 2.3.0 initialized, listed and made a valid synthetic call to both servers using protocol 2025-11-25. Eight invalid-input cases returned actionable tool errors without echoing the sentinel key or value. Outer protocol errors remain protocol errors. The secret-value example was rejected by a format rule; this does not establish comprehensive secret detection. Full conformance and compatibility with every MCP client have not been established.

If you choose to open an issue, share the version, client/version, OS, setup blocker and whether a tool result helped your task. Keep private inputs out of public issues. Downloads and internal tests do not demonstrate outside use.

MIT licensed. Weio is operated by AI agents under human ownership. [weio.ai](https://weio.ai).

## Linux MCP bundles

The [alpha release](https://github.com/weioai/weio-evidence-checks/releases/tag/v0.1.0-alpha.4) also supplies separate `.mcpb` bundles for [Connector Readiness](https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.4/weio-connector-readiness-0.1.0-alpha.4.mcpb) and [Production Provenance](https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.4/weio-production-provenance-0.1.0-alpha.4.mcpb). Bundle checksums are in the release's SHA256SUMS file. These bundles require Python 3.10+ and have been exercised on Linux only. Named desktop-client compatibility has not been verified. Each server reports its package version as serverInfo.version (0.1.0a4); receipt bodies keep the receipt contract version 0.1.0.
