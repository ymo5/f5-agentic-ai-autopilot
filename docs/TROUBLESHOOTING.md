# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `scripts/run-demo.sh`: "Python 3.12 is required" | No `python3.12` on PATH | Install Python 3.12, or `PYTHON=/path/to/python3.12 scripts/run-demo.sh` |
| Demo starts but the browser shows "login required" | You opened `/` instead of the dev shortcut | Open `http://127.0.0.1:8765/dev-login?u=se` |
| Web container exits: `AUTOPILOT_SESSION_SECRET must be set (>= 32 chars)` | Secrets file missing or not mounted | `scripts/gen-secrets.sh`, check `APLAB_SECRETS` in `.env`, and check that the container can read `autopilot.env` (group 10010) |
| Login always fails after installation | No account yet | `scripts/bootstrap-admin.sh` (see [AUTHENTICATION.md](AUTHENTICATION.md)) |
| `bootstrap refused: accounts already exist` | Bootstrap closes after the first account | Use `scripts/bootstrap-admin.sh add <name> <role>` (local admin) |
| Login returns 429 | 5 failed attempts → 10-minute lock for that account | Wait, or check the audit log for `auth.login.throttled` |
| Deploy button disabled for the owner | Two-person rule | Deploy with an `approver` account. The owner opens the live window |
| "deployment service unavailable" | Deployer not running (credential files missing) or token mismatch | `docker compose logs autopilot-deployer`; check the files in [CONFIGURATION.md](CONFIGURATION.md#deployer-credential-files); `AUTOPILOT_DEPLOYER_TOKEN` must equal `deployer/deployer_token` |
| Deploy refused: window closed | No live window, or it expired | Owner: Control center → open window. Requires `window-broker-setup.sh` |
| Deploy refused: approval invalid | Package or device changed since approval, approval expired (2 h), or review older than 30 min | Review again (preview/diff/preflight), then approve again |
| Deployer refuses to connect to BIG-IP | Certificate pin mismatch | Update `deployer/bigip_cert_sha256` (hex SHA-256 of the DER certificate) after verifying the device out of band |
| Preflight warns about memory/swap | BIG-IP control-plane memory pressure | Add memory to the VE. Only for an isolated lab device: `lab_policy.swap_informational_devices` |
| Validation gate fails on load distribution | Clients reuse one keep-alive connection, or a pool member is down | Check member health on BIG-IP; the validator uses independent connections by design |
| Enumerate finds nothing | Scope does not include the services, or a firewall blocks the Autopilot host | Check `enumerate.scope_cidrs` / `approved_hosts` / `ports` and host nftables rules |
| Ingest finds no traces | Wrong Jaeger URL, traces older than `ingest.lookback`, or services excluded | Check `ingest.*` and that the agents export OTLP |
| Observe snapshot upload 401 | `AUTOPILOT_OPERATOR_TOKEN_SHA256` unset or wrong | Set it to the SHA-256 (hex) of the token stored in the collector's Keychain item |
| AI Operations shows "no data" | No deployer, no data VIPs deployed, or no statistics yet | Expected in the simulated demo. In a lab, deploy AI Data Delivery and wait for the next refresh |
| Browser tests fail to start | Chrome not found | `CHROME_BIN=/path/to/chrome node devtools/browser/run.mjs` |

Logs: `docker compose logs -f autopilot autopilot-deployer`. The audit trail is on the **Audit** page (or in the
`audit` table).
