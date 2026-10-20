# Configuration

Configuration has four layers. Only the first two belong in a working copy of this repository, and neither is committed
(`.gitignore` covers them).

| Layer | File | Secret? | Template |
|---|---|---|---|
| Compose settings | `deploy/autopilot/.env` | no | `deploy/autopilot/.env.example` |
| Autopilot design and scope | `deploy/autopilot/autopilot.local.yaml` | no | `deploy/autopilot/autopilot.example.yaml` |
| Web secrets | `${APLAB_SECRETS}/autopilot.env` | **yes** | `deploy/autopilot/autopilot.env.example` (`scripts/gen-secrets.sh` generates it) |
| Deployer credentials | `${APLAB_SECRETS}/deployer/*` | **yes** | described below. Never generated with real values by this repository |

## Environment variables (web container)
| Variable | Default | Meaning |
|---|---|---|
| `AUTOPILOT_CONFIG` | `/etc/autopilot/autopilot.yaml` | Path of the YAML configuration |
| `AUTOPILOT_DB` | `/var/lib/autopilot/autopilot.db` | SQLite database (shared with the deployer) |
| `AUTOPILOT_SNAPSHOTS` | — | Directory for uploaded Observe snapshots |
| `AUTOPILOT_SNAPSHOT_KEEP` | `20` | Newest uploaded snapshots kept per device |
| `BIND_HOST` / `BIND_PORT` | `127.0.0.1` / `8000` | Listen address (compose: `AUTOPILOT_BIND_HOST/PORT`) |
| `TLS_CERTFILE` / `TLS_KEYFILE` | unset | Serve HTTPS directly (both required; half-configured TLS is refused) |
| `AUTOPILOT_TRUST_PROXY_PROTO` | unset | `1` = trust `X-Forwarded-Proto: https` from a TLS proxy you control (enables Secure cookies + HSTS) |
| `AUTOPILOT_SESSION_SECRET` | **required** | HMAC key for session cookies, ≥ 32 characters |
| `AUTOPILOT_SESSION_TTL` | `28800` | Session lifetime in seconds |
| `AUTOPILOT_DEPLOYER_URL` / `AUTOPILOT_DEPLOYER_TOKEN` | — | Loopback deployer URL and shared token |
| `AUTOPILOT_OPERATOR_TOKEN_SHA256` | unset | SHA-256 of the bearer token allowed to `POST /api/observe/snapshot` (collector upload). Unset = uploads refused |
| `AS3_SCHEMA` | image path | AS3 JSON schema used to validate generated declarations |
| `AUTOPILOT_PKI` | `/opt/aplab/pki` | CA bundle + validator client identities (validation tests) |
| `AUTOPILOT_TRAFFICGEN_DIR` | `/var/lib/ap-trafficgen` | Traffic Generator status directory (read-only) |
| `AUTOPILOT_TRACE_SUMMARY_DIR` | `/var/lib/autopilot/trace-summaries` | Sanitised investigation summaries; `""` disables |
| `LLM_PROVIDER` | `none` (or `openai-compatible` if `LLM_BASE_URL` is set) | `none` \| `openai-compatible` \| `anthropic` |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_TIMEOUT`, `LLM_API_KEY` | — | OpenAI-compatible endpoint (e.g. Ollama `http://<host>:11434/v1`, model `qwen2.5:3b`) |
| `ANTHROPIC_API_KEY` | — | For `LLM_PROVIDER=anthropic`. Set `LLM_MODEL` to a current Claude model id |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | Export Autopilot's own traces |

## Environment variables (deployer container)
| Variable | Default | Meaning |
|---|---|---|
| `DEPLOYER_SECRETS` | `/run/secrets/deployer` | Credential directory (read-only mount) |
| `DEPLOYER_LIVE_WINDOW` | `/run/live-window/window.json` | Root-owned window file (read-only mount). Absent = locked |
| `DEPLOYER_WINDOW_BROKER` | `/run/ap-window/broker.sock` | Window broker socket |
| `DEPLOYER_TRAFFICGEN_BROKER` | unset | Traffic broker socket (optional overlay) |
| `DEPLOYER_PORT` | `8100` | Always bound to 127.0.0.1 |

## Deployer credential files
All files live in `${APLAB_SECRETS}/deployer/`. Use mode 0440/0640, readable by the deployer user (uid 10002) and
group 10010 only. Create them yourself with values from **your** lab:

| File | Content |
|---|---|
| `deployer_token` | Same random value as `AUTOPILOT_DEPLOYER_TOKEN` (`scripts/gen-secrets.sh` writes it) |
| `bigip_cert_sha256` | Hex SHA-256 of the BIG-IP management certificate in DER form (colons allowed). The deployer refuses to connect if the presented certificate differs |
| `bigip_deployer.json` | `{"username": "...", "password": "..."}`: BIG-IP account allowed to post AS3 to the tenant |
| `bigip_observer.json` | `{"username": "...", "password": "..."}`: read-only BIG-IP account (Observe, statistics, read-back) |
| `apdeploy_ed25519` | SSH private key whose public key is installed by `deploy/common/dep-helper-setup.sh` (forced command) |
| `known_hosts` | Pinned SSH host keys of the lab VMs |
| `window_broker_key` | Copy of `/etc/aplab/window-broker.key` (`window-broker-setup.sh` creates it) |
| `trafficgen_broker_key` | Optional, `trafficgen-broker-setup.sh` creates it |

Write the JSON files without putting secrets on a command line, for example with `umask 077; cat > bigip_observer.json`,
then paste the content and press Ctrl-D.

## `autopilot.local.yaml`
Start from `autopilot.example.yaml`. Its sections:
| Section | Purpose |
|---|---|
| `observe` | `bigip_mgmt` (management address) and `mode: snapshot` (uploaded) or live via the deployer's observer |
| `enumerate` | `scope_cidrs`, `approved_hosts`, `ports`, `dns_server`, `dns_zone`, owner-provided `inventory`. **Enumerate never probes outside this scope** |
| `ingest` | Jaeger URL, lookback, limit, services/peers to exclude (Autopilot never discovers itself) |
| `identities`, `validation_identities` | OTel service → mTLS identity (certificate CN). Validator identity and its allowed tools |
| `design` | Tenant, VLANs, self IPs, VIPs, certificate objects, rate limit, front-door names, per-profile expected state (DNS, agent health, agent card), optional `data_delivery` |
| `convergence` | Post-change readiness barrier timing |
| `validation` | Agent endpoints used by validation; `data.s3_credentials_env` for an optional read-only S3 check |
| `fraud_app` | Demo application endpoints and health checks |
| `deployer_policy` | Optional: the deployer's VIP range, pool-member range and SSH helper host addresses. Defaults are the reference topology. Private IPv4 only, /16 or smaller, ranges must not overlap, exactly the three host roles. An invalid section stops start-up (fail-closed) |
| `lab_policy` | Optional lab-only overrides (commented out in the template) |

Keep `design` consistent with `deployer_policy`. The deployer refuses VIPs and members outside those ranges.

## Observe collector (operator workstation, macOS)
`scripts/observe-collect.sh` performs read-only BIG-IP REST GETs over pinned TLS and writes a redacted snapshot. It
can optionally upload the snapshot to Autopilot. Credentials come from the macOS Keychain. Configure it by copying
`config/*.example` to `config/` (git-ignored).
