# Installation

There are three ways to run the project, from no infrastructure to the full reference lab. Pick the one that matches what you have.

| Tier | You need | You get | Validation status of these instructions |
|---|---|---|---|
| **A. Simulated demo** | Python 3.12 | Real web app + UI on mocks and fixtures; full 7-stage walkthrough | Validated on macOS (Apple silicon), Python 3.12.13 |
| **B. Autopilot host** | Linux + Docker | Web UI/API with real accounts. Discovery against your own scope. The deployer is enabled only once credentials exist | Scripts reviewed and statically checked (shellcheck). **Not executed end-to-end on a clean Docker host for this release** (no Docker on the build workstation). The CI workflow builds the image |
| **C. Full reference lab** | BIG-IP VE 21.1 + AS3 3.56, lab VMs, isolated networks, PKI | End-to-end discovery → deployment → validation | Matches the topology the project was developed on. These steps are a guide, not an automated installer |

## Supported platforms
- **Demo / tests:** macOS 14+ or Linux with Python 3.12. Optional: Node.js ≥ 18 and Google Chrome (browser suite, screenshots).
- **Containers:** Linux x86_64 or arm64, Docker Engine 24+ with the compose v2 plugin. The image is built from
  `python:3.12-slim` (`deploy/common/Dockerfile`). The reference lab used Ubuntu 24.04 LTS with `docker.io` and
  `docker-compose-v2`.
- **Windows:** not tested.

## Tier A — simulated demo
```bash
scripts/run-demo.sh                 # port 8765, scenario failed-then-deployed
scripts/run-demo.sh 8765 empty      # start with an empty assessment
```
Then open `http://127.0.0.1:8765/dev-login?u=se`. The users are `viewer`, `se` (operator), `approver` and `owner`.

Scenarios:
- `empty`
- `discovered`
- `failed-then-deployed` (default)
- `compare`
- `placement-evidence`

Everything in this mode is simulated: BIG-IP, hosts, agents and validation results. Stop it with Ctrl-C. Each run
uses a new temporary database.

## Tier B — Autopilot on a Docker host
### 1. Get the code
```bash
sudo git clone <this-repository> /opt/aplab/src && cd /opt/aplab/src
```
`/opt/aplab/src` is the path the reference lab used. Other paths work for the Autopilot compose file, which builds
from the repository root. The lab-VM compose files in `deploy/agent-*` and `deploy/ai-services` expect `/opt/aplab/src`.

### 2. Install
```bash
sudo scripts/install-autopilot.sh
```
The script:
1. checks Docker;
2. creates `deploy/autopilot/.env` and `deploy/autopilot/autopilot.local.yaml` from the examples;
3. creates `/var/lib/autopilot` (uid 10001, gid 10010) and the secrets directory;
4. generates `autopilot.env` and `deployer/deployer_token` (random, mode 0600/0640, never printed);
5. builds the image `aplab-py:0.1`;
6. starts the **web** container.

It starts the deployer **only** if its credential files exist (see [CONFIGURATION.md](CONFIGURATION.md#deployer-credential-files)).

Edit `deploy/autopilot/autopilot.local.yaml` for your environment before running discovery. Then restart:
`cd deploy/autopilot && docker compose up -d`.

### 3. Database initialisation
No manual step is needed. The web and deployer services create their SQLite schema (`CREATE TABLE IF NOT EXISTS`) in
`${AUTOPILOT_DATA}/autopilot.db` on first start.

### 4. First administrator
```bash
scripts/bootstrap-admin.sh                   # owner account, hidden password prompt
scripts/bootstrap-admin.sh add alice approver
scripts/bootstrap-admin.sh add sam operator
```
See [AUTHENTICATION.md](AUTHENTICATION.md).

### 5. Health check
```bash
scripts/healthcheck.sh       # web /healthz, auth enforced (/api/me -> 401), compose status, deployer /healthz
```

### 6. Optional components
| Component | How |
|---|---|
| Live-window broker (required for any live deployment) | `sudo bash deploy/common/window-broker-setup.sh` (run from `/opt/aplab/src`). It creates group `apwin` (10020), the socket and the HMAC key copy for the deployer |
| Traffic Generator | `traffic-generator/container/build.sh`, `install.sh <BUILD_ID>` (reference-lab installer: pinned base image digest, adapt `BASE_ID`), `trafficgen-broker-setup.sh install`, then `docker compose -f docker-compose.yml -f docker-compose.trafficgen.yml up -d` |
| LLM assistance | Set `LLM_PROVIDER` / `LLM_BASE_URL` / `LLM_MODEL` in `.env` (or `ANTHROPIC_API_KEY` in `autopilot.env`) |
| TLS for the UI | Set `TLS_CERTFILE` and `TLS_KEYFILE` (both required) in the web environment, or put a TLS proxy in front and set `AUTOPILOT_TRUST_PROXY_PROTO=1` |

## Tier C — full reference lab
The project was developed on this topology. Replace every address with yours, consistently.

1. **Networks:** a management LAN, plus two isolated L2 segments without uplink: agent `10.50.10.0/24` and backend
   `10.50.20.0/24`.
2. **BIG-IP VE 21.1** (LTM provisioned) with AS3 ≥ 3.56 installed from F5's official release. Create self IPs on both
   VLANs, a lab CA bundle, a wildcard certificate/key as `/Common` objects, an observer (read-only) account and a
   deployer account.
3. **Lab VMs** (Ubuntu 24.04): run `deploy/common/host-setup.sh` on each (Docker with iptables disabled, nftables, ip_forward=0).
   - **AI services VM:** `deploy/ai-services/deploy.sh`. It generates S3 credentials on the VM, synthetic data, pulls
     `qwen2.5:3b` + `nomic-embed-text`, then starts Qdrant/SeaweedFS/Ollama/CoreDNS/OTel/Jaeger/MCP servers and seeds data.
   - **Agent B VM** and **Agent A VM:** `docker compose up -d` in `deploy/agent-b` / `deploy/agent-a`.
   - On each VM: `deploy/common/dep-helper-setup.sh <role>` with the deployer's SSH **public** key on stdin. This sets up
     the forced-command helper `ap-dep-apply` and the host profiles.
4. **PKI:** generate a lab CA, server certificates for the front-door names, and client certificates for `agent-a`,
   `agent-b`, `ap-validator` (and `ap-unauthorized` for negative tests). Place the CA bundle and validator identities
   in `${APLAB_PKI}`. No PKI material ships with this repository.
5. **Autopilot host:** Tier B, plus the deployer credential files and the window broker.
6. **Adapt the deployer policy:** `app/autopilot/deployer/policy.py` (`VIP_RANGE`, `MEMBER_RANGE`, `HOSTS`,
   `BIGIP_REFS`) must match your lab.

## Upgrade
1. `cd /opt/aplab/src && git pull` (review the changes first).
2. Back up: `sqlite3 /var/lib/autopilot/autopilot.db ".backup /var/backups/autopilot-$(date -u +%Y%m%dT%H%M%SZ).db"`.
3. `cd deploy/autopilot && docker compose build && docker compose up -d`.
4. `scripts/healthcheck.sh`.

Schema changes are additive (`CREATE TABLE IF NOT EXISTS`). To roll back, restore the previous image or commit plus the database backup.

## Uninstall
```bash
cd /opt/aplab/src/deploy/autopilot && docker compose down          # stops web + deployer
sudo systemctl disable --now ap-window-broker.socket                # if installed
sudo bash traffic-generator/container/trafficgen-broker-setup.sh uninstall <backup-dir>   # if installed
# data and secrets are NOT removed automatically:
sudo rm -rf /var/lib/autopilot /opt/aplab/secrets                   # only when you are sure (destroys accounts and audit)
```
Uninstalling Autopilot does not change BIG-IP. Before uninstalling, roll back or Reset Demo from the UI if you want
to remove the deployed `AP_AI` tenant.
