# Security design and operating guidance

This is a lab prototype. The controls below are implemented and tested offline, but the project has **not** had an
independent security review. Do not connect it to production devices.

## Threat model (summary)
| Asset | Threat | Control |
|---|---|---|
| BIG-IP configuration | Unapproved or unintended change | Deployer-only credentials; exact `approver` role; hash- and fingerprint-bound, expiring, single-use approvals; owner-opened live window held in a root-owned file; AS3 policy (single tenant, class allow-list, pinned `/Common` references, VIP/member ranges); dry-run; validation gate; automatic, verified rollback |
| Lab hosts | Arbitrary command execution | SSH forced command `ap-dep-apply` behind sudo, with a fixed command allow-list (`status`, `profile baseline|delivery|security`, `replica stop|start 1|2`, `probe direct-mcp`). The key is restricted by `from=` |
| Device credentials | Disclosure through the web tier | Held only by the deployer container (uid 10002), which is loopback-only, read-only mounted and never returned by any API |
| Accounts | Takeover / escalation | scrypt hashes; HMAC-signed sessions; CSRF double-submit; per-account lockout; local-only bootstrap that closes after first use; no account APIs |
| Root brokers | Privilege abuse | Unix sockets restricted to a dedicated group, HMAC + timestamp ±60 s + single-use nonce, fixed action tables, rate limits |
| Discovery scope | Probing outside the approved scope | Enumerate is limited to `scope_cidrs`, `approved_hosts` and fixed ports. Discovery never writes |
| Evidence and reports | Leaking secrets in captured data | The collector redacts secret-named fields, auth headers, iRule source and monitor send/recv strings. The JSON viewer and downloads redact secret-named keys |
| LLM | Prompt injection influencing change control | LLM output only produces *asserted* components and narrative text. It cannot approve, deploy or alter generated configuration |

## HTTP hardening (web)
The web service sets `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` and
related headers. Over HTTPS (direct TLS or a trusted proxy) it adds `Secure` cookies and HSTS.

## Secrets handling rules used by this project
- Secrets are never passed on a command line, in an environment listing, a log or a chat. The test
  `test_no_secrets_in_process_arguments` checks scripts and code for common anti-patterns.
- Generated secrets (`scripts/gen-secrets.sh`) are written with mode 0600 and never printed.
- No secrets, keys, certificates, kubeconfigs, device backups, databases or logs are part of this repository.
  `.gitignore` blocks the usual file types as a second line of defence.

## Operating guidance
1. Keep the UI on 127.0.0.1 or a management network. Enable TLS before allowing remote access.
2. Create separate `owner` and `approver` accounts held by different people.
3. Use a **read-only** BIG-IP account for the observer and a deployer account limited to what AS3 needs. The
   reference lab used admin accounts on a dedicated, isolated lab device. Do not copy that choice.
4. Review `app/autopilot/deployer/policy.py` for your lab before enabling the deployer.
5. Back up the SQLite database regularly. It contains the audit trail.
6. Rotate `AUTOPILOT_SESSION_SECRET` and `AUTOPILOT_DEPLOYER_TOKEN` (and `deployer/deployer_token`) when people leave.

## Publication hygiene (how this repository was prepared)
- It was built from an explicit file allowlist, not by copying a development tree.
- No development history is included.
- Management addresses were replaced with the RFC 5737 documentation range `192.0.2.0/24`. The isolated data-plane
  ranges `10.50.10.0/24` / `10.50.20.0/24` remain as the documented reference topology.
- Tests that needed the lab PKI now generate throwaway certificates at run time.
- Scanned with gitleaks and trufflehog, plus manual pattern searches.

## Reporting a vulnerability
See the repository root [SECURITY.md](../SECURITY.md).
