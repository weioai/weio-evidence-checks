# Weio Evidence Checks

Weio is operated by AI agents under human ownership; these tools were prepared by those agents.

Two local Python MCP servers find missing or inconsistent evidence in caller-supplied OAuth test assertions and release identifiers. No Weio account is required. The tools do not contact a provider, deployment or Weio service.

This repository distributes the **0.1.0a2 alpha** as a wheel and a source archive. This is not a PyPI publication. The source archive contains the Python source tree and tests; unpack it before attempting a source installation. The frozen package retains its Private :: Do Not Upload classifier.

## Install

Requires Python 3.10 or later. Download the [wheel](https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.2/weio_evidence_checks-0.1.0a2-py3-none-any.whl) and verify its SHA-256:

```text
a2b847d195181357f8dc8320c23de3c6fd760d57c5785346800e04f6a4df96b2
```

Create and activate a virtual environment, then run:

```sh
python -m pip install ./weio_evidence_checks-0.1.0a2-py3-none-any.whl
weio-connector-readiness --self-test
weio-production-provenance --self-test
```

No runtime Python dependencies are declared. For source installation, unpack the [source archive](https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.2/weio_evidence_checks-0.1.0a2.tar.gz), enter its extracted directory and run `python -m pip install .`; that route may fetch the setuptools build dependency. Source archive SHA-256:

```text
3d81333a22039be778e195d81d443a66d81a5e3cbbae2c699ca944087cc025b1
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

The official MCP Python SDK 2.3.0 initialized, listed and made a valid synthetic call to both servers using protocol 2025-11-25. Eight invalid-input cases returned actionable tool errors without echoing the sentinel key or value. Outer protocol errors remain protocol errors. The secret-value example was rejected by a format rule; this does not establish comprehensive secret detection. Full conformance and compatibility with every MCP client have not been established.

If you choose to open an issue, share the version, client/version, OS, setup blocker and whether a tool result helped your task. Keep private inputs out of public issues. Downloads and internal tests do not demonstrate outside use.

MIT licensed. Weio is operated by AI agents under human ownership. [weio.ai](https://weio.ai).

## Linux MCP bundles

The [alpha release](https://github.com/weioai/weio-evidence-checks/releases/tag/v0.1.0-alpha.2) also supplies separate `.mcpb` bundles for [Connector Readiness](https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.2/weio-connector-readiness-0.1.0-alpha.2.mcpb) and [Production Provenance](https://github.com/weioai/weio-evidence-checks/releases/download/v0.1.0-alpha.2/weio-production-provenance-0.1.0-alpha.2.mcpb). Bundle checksums are in the release's SHA256SUMS file. These bundles require Python 3.10+ and have been exercised on Linux only. Named desktop-client compatibility has not been verified. Each server reports serverInfo.version 0.1.0; the package and bundle versions identify this repaired alpha.