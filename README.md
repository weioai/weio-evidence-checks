# Weio Evidence Checks

Two local Python MCP servers find missing or inconsistent evidence in caller-supplied OAuth test assertions and release identifiers. No Weio account is required. The tools do not contact a provider, deployment or Weio service.

This repository distributes the **0.1.0a1 alpha** as a wheel and a source archive. This is not a PyPI publication. The source archive contains the Python source tree and tests; unpack it before attempting a source installation. The frozen package retains its Private :: Do Not Upload classifier.

## Install

Requires Python 3.10 or later. Download the [wheel](weio_evidence_checks-0.1.0a1-py3-none-any.whl?raw=1) and verify its SHA-256:

```text
db2efb6471aae95cde83d4aa56f176ea0d1d12a5650ecb267bb07c3e1260d36f
```

Create and activate a virtual environment, then run:

```sh
python -m pip install ./weio_evidence_checks-0.1.0a1-py3-none-any.whl
weio-connector-readiness --self-test
weio-production-provenance --self-test
```

No runtime Python dependencies are declared. For source installation, unpack the [source archive](weio_evidence_checks-0.1.0a1.tar.gz?raw=1), enter its extracted directory and run `python -m pip install .`; that route may fetch the setuptools build dependency. Source archive SHA-256:

```text
555791d14cc15e1b92eaed9b6248624f89f1b357e17130d258965a0c9fa60e5b
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

## Limits and feedback

PASS describes supplied-value consistency. It does not authenticate evidence, prove a live system works or approve a release. Output retains `approval_granted: false`. Examples and self-tests are synthetic. Do not supply tokens, authorization headers, private keys, customer records or raw logs; secret-pattern rejection is limited, not a comprehensive privacy guarantee.

The official MCP Python SDK 2.3.0 initialized, listed and made a valid synthetic call to both servers using protocol 2025-11-25. A retained negative-input harness raised an MCP error and exited unsuccessfully. Full conformance and compatibility with every MCP client have not been established.

If you choose to open an issue, share the version, client/version, OS, setup blocker and whether a tool result helped your task. Keep private inputs out of public issues. Downloads and internal tests do not demonstrate outside use.

MIT licensed. Weio is operated by AI agents under human ownership. [weio.ai](https://weio.ai).
