# Known limitations

## Scope and maturity
- **Lab prototype for a competition submission.** It is not production software, has had no independent security
  review, and is not an F5 product.
- **One BIG-IP deployment target.** The placement advisory can reason about several devices, but the deployer deploys
  only to the device in `observe.bigip_mgmt`. There is no HA / device-group awareness for deployment.
- **Reference topology in code.** `app/autopilot/deployer/policy.py` pins the tenant (`AP_AI`), VIP/member ranges, the
  lab host names and addresses, and `/Common` object names. Templates assume BIG-IP **21.1** and AS3 **≥ 3.56**. Other
  topologies need code and config changes.
- **Templates target the reference application:** A2A + MCP agents, Qdrant, S3 (SeaweedFS), Ollama. Other AI stacks are
  discovered generically but may not produce packages.
- **SQLite, single host.** No clustering. Concurrency is limited to one deployment at a time.

## Authentication
- Local accounts only: no SSO/OIDC/LDAP and no MFA.
- Accounts are managed with a local CLI. There is no account-management UI.
- Sessions are stateless signed cookies. Disabling an account or changing a role takes effect at the next login. Rotate
  the session secret to revoke all sessions.
- Login lockout is per account (5 failures → 10 minutes). Someone who knows a username can therefore keep that account
  locked (availability, not confidentiality).

## Installation and reproducibility
- **The simulated demo and the offline test suites were validated.** The Docker installation scripts were reviewed and
  statically checked but **not executed on a clean Docker host** for this release. The CI workflow builds the image.
- The full lab requires licensed F5 software (BIG-IP VE, AS3 from F5's release), several VMs, isolated networks and a
  PKI that you create. None of this is automated end-to-end.
- The Traffic Generator installer (`traffic-generator/container/install.sh`) is the reference lab's guarded release
  installer. It pins the lab's base-image digest, which must be adapted.
- `docker-compose.trafficgen.yml` is reconstructed from release notes and was not run as-is.
- The UI defaults to HTTP. TLS is supported but must be configured.

## Functionality
- **AI Operations** shows BIG-IP statistics only for the AI data VIPs (through the deployer's observer). Per-VIP time
  series, TLS handshake counters and iRule activity are **not** collected. That requires an external observability
  platform, which is not included.
- Observe "live" mode requires the deployer's observer account. The default is operator-uploaded snapshots.
- The demo application's data (accounts, transactions, alerts, case files, fraud patterns) is **synthetic**. Risk
  scoring is an illustrative model, not a trained fraud model.
- LLM output (Describe, Agent B narrative) depends on the model. Small local models (`qwen2.5:3b`) can be inaccurate.
  Results are labelled with provider and model, and deterministic fallbacks are labelled as such.
- Five tests are skipped outside the lab: four need a captured real AS3 Security declaration
  (`F5_REAL_SECURITY_DECL`), and one needs the lab PKI.
- The Traffic Generator's offline tests that depend on the separate Control Center desktop application are not
  included. The engine also contains a second, legacy environment profile (`project-b`) whose configuration is not
  part of this repository.

## Licensing and publication
- **No open-source licence has been selected yet.** Choose one (e.g. Apache-2.0 or MIT) before public release, and
  confirm you have the right to license all included code.
- "F5", "BIG-IP" and related names are F5, Inc. trademarks. The F5 logo is **not** included. Confirm trademark usage
  (including the project name) before public release.
- `packages/vendor/as3-schema-3.56.0-10.json` comes from F5's AS3 project. Confirm its licence terms (the AS3 project
  is published under Apache-2.0) before public redistribution, or download it at build time instead.
- AI model weights are never included. Check the licence of any model you pull. For example, Qwen2.5-3B uses the Qwen
  Research License, not Apache-2.0.
