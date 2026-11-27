# Security Policy

## Supported Versions

Security fixes are released for the latest minor version of Piton (`piton-cli` and `piton-sidecar`):

| Version | Supported |
| :--- | :---: |
| `0.4.x` | ✅ |
| `< 0.4.0` | ❌ |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, email **bright@gaussianlabs.dev** with:
- A description of the vulnerability and affected component (`piton` CLI, GitHub Action, Go Envoy `ext_proc` sidecar, or Control Plane)
- Minimal reproduction steps or proof-of-concept
- Any suggested mitigation or patch

### Response Targets
- **Acknowledgement:** within 48 hours
- **Triage & severity assessment:** within 5 business days
- **Fix & coordinated disclosure:** prioritized for Critical/High findings

## Safe Probing & Deployment Defaults

- `piton init --probe` and `piton lock --probe` run static supply-chain scanning **before** probing and refuse to execute local STDIO MCP commands unless `--allow-stdio-exec` is explicitly passed.
- Production deployments of `piton-sidecar`, `piton wrap --enforce`, and `piton control-plane` require an explicit `PITON_LEDGER_SIGNING_KEY` and `PITON_CONTROL_API_KEY`.
