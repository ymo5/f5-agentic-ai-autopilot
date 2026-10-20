#!/usr/bin/env bash
# First-run administrator setup for a Docker installation (interactive; run on the Autopilot host).
# Creates the FIRST account (role owner) with a username and password YOU choose. The password is read from a hidden
# prompt inside the container; it is never placed on the command line, in the environment or in a log.
# Refused automatically once any account exists. Further accounts: scripts/bootstrap-admin.sh add <name> <role>
set -euo pipefail
cd "$(dirname "$0")/../deploy/autopilot"
if [ "${1:-}" = "add" ]; then
  shift; exec docker compose exec -it autopilot python -m autopilot.auth add "$@"
fi
exec docker compose exec -it autopilot python -m autopilot.auth bootstrap "$@"
