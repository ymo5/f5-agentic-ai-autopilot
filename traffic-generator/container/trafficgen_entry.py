#!/usr/bin/env python3
"""Container entrypoint of the Project A traffic generator (ap-trafficgen). Bounded runs only.

  trafficgen_entry.py --duration SECONDS [--only w1,w2] [--max-rpm N]
  trafficgen_entry.py --once [--only w1,w2] [--max-rpm N]
  trafficgen_entry.py --dry-run

Everything else is fixed here and cannot be changed from the command line: the profile (project-a.json baked into the
image), the instance (pa_lab), the status file and the stop file on the /state volume. There is no continuous mode:
--duration is capped at TG_MAX_DURATION_S (default 3600, never above 7200). A hard backstop alarm is armed before the
engine starts, so the process ends even if a request hangs past the duration (SIGALRM survives exec).
"""
import argparse, os, signal, sys

ENGINE = "/opt/trafficgen/simulator/f5_ai_workload_sim.py"
PROFILE = "/opt/trafficgen/simulator/profiles/project-a.json"
STATE = "/state"
HARD_MAX = 7200
BACKSTOP_GRACE_S = 120                     # longest single request timeout (chat 90 s) + margin
NAME_RE = __import__("re").compile(r"^[a-z0-9_]{1,40}(,[a-z0-9_]{1,40}){0,15}$")


def build(argv, environ=None):
    """-> (engine argv, backstop seconds or None). Raises SystemExit on any invalid request."""
    env = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(prog="ap-trafficgen")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--duration", type=int); g.add_argument("--once", action="store_true"); g.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only"); ap.add_argument("--max-rpm", type=int)
    a = ap.parse_args(argv)
    try:
        limit = int(env.get("TG_MAX_DURATION_S", "3600"))
    except ValueError:
        ap.error("TG_MAX_DURATION_S must be an integer")
    limit = max(60, min(limit, HARD_MAX))
    if a.duration is not None and not 60 <= a.duration <= limit:
        ap.error(f"--duration must be 60..{limit} seconds")
    if a.only is not None and not NAME_RE.match(a.only):
        ap.error("--only must be a comma-separated list of workload names")
    if a.max_rpm is not None and not 1 <= a.max_rpm <= 60:
        ap.error("--max-rpm must be 1..60")
    out = [sys.executable, "-B", ENGINE, "--config", PROFILE, "--instance", "pa_lab",
           "--status-file", f"{STATE}/status.json", "--stop-file", f"{STATE}/STOP"]
    if a.dry_run:
        out.append("--dry-run")
    elif a.once:
        out.append("--once")
    else:
        out += ["--duration", str(a.duration)]
    if a.only:
        out += ["--only", a.only]
    if a.max_rpm:
        out += ["--max-rpm", str(a.max_rpm)]
    backstop = None if a.dry_run else (a.duration or 1800) + BACKSTOP_GRACE_S
    return out, backstop


def main():
    argv, backstop = build(sys.argv[1:])
    if backstop:
        signal.alarm(backstop)
    os.execv(argv[0], argv)


if __name__ == "__main__":
    main()
