#!/usr/bin/env python3
"""Extract the parser-validation subset of a local Observe capture, for sharing (offline; no network).

Usage: python3 -I scripts/observe-share.py <capture.json> <share.json>

Keeps only what the Wave 3 placement parsers read — device version and provisioning, AS3 availability, self IPs, routes,
failover status, device groups, memory, CPU and the collector metadata (timings, collection time, device label and
address) — and drops everything else (virtual servers, pools, monitors, iRules, SSL profiles, log destinations, host name).
Secret-named fields and authorization headers are redacted again (defence in depth; the collector already redacts).
The memory response is reduced to its memory-host entries and the CPU response to idle averages per CPU (v2).
The output file is written with mode 0600.
"""
import json
import os
import re
import sys

KEEP = ("version", "provision", "as3", "self", "route", "failover_status", "device_group", "memory", "cpu", "_meta")
SECRET = re.compile(r"(?i)(pass(phrase|word)?|secret|token|psk|shared[-_]?key|private[-_]?key)$")
AUTH = re.compile(r"(?i)(authorization|proxy-authorization|cookie|x-f5-auth-token)\s*:\s*[^\\\r\n]+")


def redact(o):
    if isinstance(o, dict):
        return {k: "[REDACTED]" if SECRET.search(k) and v not in (None, "", "none") else redact(v) for k, v in o.items()}
    if isinstance(o, list):
        return [redact(v) for v in o]
    if isinstance(o, str):
        return AUTH.sub(lambda m: m.group(1) + ": [REDACTED]", o)
    return o


def _minimize_memory(body):
    """sys/memory: keep only the memory-host entries (host, control-plane 'Other', TMM and swap totals); the hundreds of
    memory-subsys allocator entries are never parsed."""
    if isinstance(body, dict) and isinstance(body.get("entries"), dict):
        body = {**body, "entries": {k: v for k, v in body["entries"].items() if "memory-host" in k}}
    return body


CPU_FIELDS = re.compile(r"(?i)(idle|^cpuId$|^hostId$)")


def _minimize_cpu(o):
    """sys/cpu: keep the nestedStats structure but only idle averages, cpuId and hostId."""
    if isinstance(o, dict):
        if "nestedStats" in o and isinstance(o["nestedStats"], dict):
            ent = o["nestedStats"].get("entries") or {}
            keep = {k: (_minimize_cpu(v) if isinstance(v, dict) and "nestedStats" in v else v)
                    for k, v in ent.items() if (isinstance(v, dict) and "nestedStats" in v) or CPU_FIELDS.search(k)}
            return {**o, "nestedStats": {**o["nestedStats"], "entries": keep}}
        return {k: _minimize_cpu(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_minimize_cpu(v) for v in o]
    return o


def main(src: str, dst: str) -> None:
    raw = json.load(open(src))
    out = {k: redact(raw[k]) for k in KEEP if k in raw}
    if isinstance(out.get("memory"), dict) and "body" in out["memory"]:
        out["memory"]["body"] = _minimize_memory(out["memory"]["body"])
    if isinstance(out.get("cpu"), dict) and "body" in out["cpu"]:
        out["cpu"]["body"] = _minimize_cpu(out["cpu"]["body"])
    if "as3" in out and isinstance(out["as3"].get("body"), dict):        # AS3 info: version only
        out["as3"]["body"] = {k: v for k, v in out["as3"]["body"].items() if k in ("version", "release", "schemaCurrent")}
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    os.chmod(dst, 0o600)
    print(f"wrote {dst}: {', '.join(k for k in KEEP if k in out)} (mode 0600)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
