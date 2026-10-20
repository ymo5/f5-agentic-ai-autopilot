# Demo walkthrough

## Simulated demo (no hardware)
```bash
scripts/run-demo.sh                 # http://127.0.0.1:8765
```
The default scenario `failed-then-deployed` pre-loads a realistic history:
- discovery of the reference application;
- an AI Delivery deployment whose validation gate **fails** and **rolls back automatically**;
- a corrected deployment that succeeds;
- a `before` validation run;
- a completed fraud investigation.

**All of this is simulated.** Mock BIG-IP and host executors and recorded fixtures stand in for the lab, and nothing
leaves your machine.

Sign in through the dev shortcut, which exists only in the demo server:
`/dev-login?u=se` (operator), `?u=approver`, `?u=owner` or `?u=viewer`.

| Step | Page | As | What to show |
|---|---|---|---|
| 1 | **Discover** | `se` | Four sources (Observe / Describe / Enumerate / Ingest), the topology graph, and the Describe panel. The interpretation is labelled "deterministic parser — not an LLM" because no LLM is configured. Two customer assertions are **contradicted by telemetry** (S-007) |
| 2 | **Assess** | `se` | Findings D-001…D-005 and S-001…S-009, each with an evidence link and a status (confirmed / inferred / contradicted / not assessable). Risk dashboard |
| 3 | **Recommend** | `se` | AI Delivery and AI Security packages: AS3, change summary, dependency plan (DNS + agent env per host), findings addressed. The placement advisory explains why it abstains or selects |
| 4 | **Approve** | `approver` | Review (preview, diff, preflight), then approve. The approval binds the package hash and device fingerprint. As `viewer` or `se`, the actions are disabled with a reason |
| 5 | **Deploy** | `approver` / `owner` | Journal of the failed attempt (gate failed → automatic rollback → rollback verified) and the successful one. The owner opens a (simulated) live window; the owner **cannot** deploy |
| 6 | **Validate** | `se` | Validation runs per profile, with pass/fail per test and observed vs expected |
| 7 | **Observe** | `viewer` | Verification levels, before/after comparison (`scripts/run-demo.sh 8765 compare`), reports (HTML / JSON) |
| + | **Fraud application** | `se` | Run an investigation (ALERT-9000…). Timeline with provenance: synthetic input, measured timings, illustrative scoring model |
| + | **AI Operations** | `viewer` | Gate and validation results, latest investigation. BIG-IP statistics show "no data" in the simulated demo because no statistics mock is wired |
| + | **Control center** | `owner` | Live-window authorisation flow (password re-entry + typed confirmation) against a simulated broker |

## Real lab demo (outline)
Prerequisites: the Tier C installation ([INSTALLATION.md](INSTALLATION.md)). All infrastructure starts in the
**baseline** profile: agents talk directly, with no BIG-IP objects in the tenant.
1. Operator: **Run discovery**. Upload a fresh Observe snapshot first if `observe.mode: snapshot`.
2. Operator: **Assess**, then **Recommend**.
3. Approver: **Review**, then **Approve** the AI Delivery package.
4. Owner: **Control center → open live window** (for example 60 minutes, with a reason).
5. Approver: **Deploy**. Watch preflight, AS3, host profiles, convergence and the gate (`after-delivery`).
6. Operator: **Validate** (`after-delivery`), run a **fraud investigation**, and check the trace path via BIG-IP.
7. Repeat for **AI Security** (`after-security`: mTLS identity, tool authorisation 403, rate limit 429) and optionally
   **AI Data Delivery** (`after-data`).
8. Operator: **New assessment → Run discovery** to compare before and after on **Observe**.
9. Approver: **Rollback** or **Reset Demo** to return to baseline. Owner: close the window.
