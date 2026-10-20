# Authentication, accounts and roles

## Model
- **Local accounts** live in the `users` table of the Autopilot SQLite database. There is no external IdP and no SSO.
- **Passwords** are hashed with scrypt (n=2^14, r=8, p=1, 16-byte random salt, 32-byte hash) and compared in constant
  time. Unknown users get a dummy hash computation, which reduces timing differences. The minimum length is 12
  characters. A `--allow-weak` lab override exists for `add` only, never for `bootstrap`.
- **Sessions** use an HMAC-SHA256-signed cookie `ap_session` containing username, role and expiry
  (`AUTOPILOT_SESSION_TTL`, default 8 h). It is `HttpOnly` and `SameSite=Strict`, and also `Secure` over HTTPS. Every
  state-changing request also needs the CSRF double-submit header `X-CSRF-Token` matching the `ap_csrf` cookie.
- **Brute-force throttling:** 5 failed logins for an account lock it for 10 minutes (`throttle.py`). Lockouts are audited (`auth.login.throttled`).
- **No service identity:** no API key, LLM or agent can obtain a session. Approval and deployment always require a
  signed-in human.

## Roles
| Role | Can |
|---|---|
| `viewer` | Read-only UI/API |
| `operator` | Discovery, assessment, recommendation, validation runs, fraud investigations, Traffic Generator presets, reset assessment |
| `approver` | Everything above, plus approve / reject / revoke packages, **deploy**, roll back, Reset Demo, close a live window |
| `owner` | Everything an approver can, plus **open a live window** (password re-entry + typed confirmation). The deployer refuses deploy/rollback/reset from the owner role (two-person rule) |

## First-run administrator bootstrap
No account and no default password ship with the project. The first account is created with a local command that
requires shell access to the host or container. It cannot be triggered over the network.

```bash
# Docker installation
scripts/bootstrap-admin.sh                 # = docker compose exec -it autopilot python -m autopilot.auth bootstrap
# Without Docker (from app/)
AUTOPILOT_DB=/var/lib/autopilot/autopilot.db python -m autopilot.auth bootstrap
```
Bootstrap behaviour:
1. It refuses with exit code 3 if **any** account already exists. The check and the insert run in one
   `BEGIN IMMEDIATE` transaction, so concurrent attempts cannot create two owners.
2. It asks for a username (2–32 characters: lowercase letters, digits, `.`, `_`, `-`) and a password, entered twice at
   a hidden prompt. Non-interactive use reads one line from stdin. The password is never accepted as an argument.
3. It creates the account with role `owner` and writes an `auth.bootstrap` audit row (username and role only).
4. It prints only the username and the next step. The password is never echoed or logged.

## Managing accounts (local administrator)
```bash
scripts/bootstrap-admin.sh add alice approver          # create (hidden prompt)
scripts/bootstrap-admin.sh add alice approver --replace  # reset password / change role (explicit)
docker compose exec autopilot python -m autopilot.auth disable alice
docker compose exec autopilot python -m autopilot.auth enable alice
docker compose exec autopilot python -m autopilot.auth list
```
- `add` refuses to overwrite an existing account unless you pass `--replace`, so roles cannot be changed by accident.
- Every change is audited as `auth.password.set` or `auth.user.disabled` / `enabled`.
- There is **no web endpoint** for creating accounts, changing roles or resetting passwords.

**Recommended minimum for deployments:** one `owner` (opens windows) and at least one **different** person with the
`approver` role (deploys).

## Session behaviour to be aware of
- The role is embedded in the signed cookie at login. A role change or disable takes effect at the next login. Existing
  sessions remain valid until they expire (≤ `AUTOPILOT_SESSION_TTL`). To revoke all sessions immediately, rotate
  `AUTOPILOT_SESSION_SECRET` and restart the web container.
- The deployer re-reads the user's role from the database for Traffic Generator actions. Deploy and rollback require
  the exact `approver` role.

## Tested properties (`app/tests/test_auth_bootstrap.py`)
1. A fresh install has no accounts, and common default credentials are rejected.
2. Bootstrap creates exactly one owner with a scrypt hash. The plaintext appears in neither the database nor the output.
3. Weak passwords and invalid usernames are rejected without creating anything.
4. Login succeeds with the chosen password. A wrong password or an unknown user gets 401.
5. Roles are assigned by the local CLI. Silent overwrite is refused, and disabled accounts cannot sign in.
6. Bootstrap is refused once configured, including under concurrency. No account-creation routes exist, and a forged
   (re-signed-without-key) role cookie is rejected.
7. Accounts persist across a restart (new process, same database).
8. The approval and deployment boundaries are unchanged: viewers and operators cannot approve, and the owner, viewer
   and operator cannot deploy.
