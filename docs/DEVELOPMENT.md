# Development

## Setup
```bash
python3.12 -m venv .venv-dev && .venv-dev/bin/pip install -r requirements-dev.txt
```

## Tests (all offline: no lab system is contacted)
```bash
scripts/run-tests.sh            # Autopilot (app/tests) + Traffic Generator (traffic-generator/simulator/tests_offline)
scripts/run-tests.sh --browser  # + headless-Chrome UI regression suite (Node ≥ 18, Google Chrome)
```
| Suite | Command | Result for this publication candidate (2026-10-20) |
|---|---|---|
| Autopilot unit/integration | `cd app && python -m pytest -q tests` | 552 passed, 5 skipped |
| Traffic Generator | `cd traffic-generator/simulator && python -m pytest -q tests_offline` | 30 passed |
| Browser (41 scenarios) | `AP_PYTHON=.venv-dev/bin/python node devtools/browser/run.mjs` | 41/41 passed |

The tests cover:
- the discovery sources, with fixtures for scans, traces and BIG-IP captures;
- assessment rules, package generation and golden packages;
- AS3 schema validation;
- approvals (hash, fingerprint, expiry, single use);
- deployment simulations on `MockBigip`/`MockHosts`, including failure injection and rollback;
- the convergence barrier and the validator against real MCP servers on loopback behind a per-connection load
  balancer (`tests/mcp_lb_harness.py`);
- the iRule policy replayed from recorded requests;
- security headers, CSRF, roles, throttling and authentication bootstrap;
- the AI Operations read model and the Traffic Generator controls.

Skipped outside the lab: `test_real_security_baseline.py` (needs `F5_REAL_SECURITY_DECL`, a captured AS3 declaration)
and one convergence test that needs the lab PKI.

## Code map
| Path | Notes |
|---|---|
| `app/autopilot/web.py` | FastAPI app, all `/api/*` routes, role dependencies, security headers |
| `app/autopilot/engine.py`, `sources/` | Discovery and reconciliation |
| `app/autopilot/catalog.py`, `assess.py`, `claims.py` | Findings catalogue and rules |
| `app/autopilot/packages.py`, `data_delivery.py` | AS3/iRule templates and the package builder |
| `app/autopilot/approvals.py` | Hash-bound approvals |
| `app/autopilot/validate.py` | Validation profiles and tests |
| `app/autopilot/deployer/` | `service.py` (API), `engine.py` (deploy/rollback), `policy.py` (safety policy), `executors.py` (real + mock executors), `converge.py`, `window.py`, `control.py`, `broker.py`, `trafficgen.py` |
| `app/autopilot/aiops.py`, `static/aiops.js` | AI Operations read model and UI |
| `app/autopilot/static/` | UI (vanilla JS; `ui-core.js` helpers; Cytoscape.js for graphs) |
| `devtools/devserver.py` | Simulated demo server (real app + mocks); never deploy it |

## Conventions
- New infrastructure-changing behaviour belongs in the deployer, behind `policy.py`. The web tier stays credential-free.
- Every value shown in the UI must state its source/kind (evidence, lifetime counter, delta, duration). Never present
  simulated data as measured.
- Secrets never go into argv, logs or tests. Tests that need certificates generate throwaway PKI.
- Run `python -m pyflakes` on changed files.

## Regenerating screenshots
```bash
AP_PYTHON=.venv-dev/bin/python node devtools/browser/screenshots.mjs docs/screenshots
```
