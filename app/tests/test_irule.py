"""Behavioural tests of the generated MCP policy iRule, executed in a local Tcl interpreter with stubbed BIG-IP
commands (HTTP::, SSL::, X509::, table, clock). Covers the bypasses found in the v2 review: chunked/oversized legacy
bodies, escaped JSON method names, reordered tool names, batches, and rate-limit lockout under sustained traffic."""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

TCLSH = shutil.which("tclsh")
pytestmark = pytest.mark.skipif(not TCLSH, reason="tclsh not available")

HARNESS = r"""
array set ev {}
set tbl [dict create]
proc when {name body} { set ::ev($name) $body }
namespace eval HTTP {}
proc HTTP::header {op name args} {
  if {$op eq "value"} { if {[info exists ::hdr($name)]} { return $::hdr($name) } ; return "" }
  if {$op eq "replace"} { set ::hdr($name) [lindex $args 0] }
}
proc HTTP::respond {code args} { set ::responded $code }
proc HTTP::method {} { return $::_verb }
proc HTTP::collect {n} { set ::collected $n }
proc HTTP::payload {} { return $::payload }
proc HTTP::release {} { set ::released 1 }
namespace eval SSL {}
proc SSL::cert {args} { if {[lindex $args 0] eq "count"} { return [expr {$::cn ne ""}] } ; return c }
namespace eval X509 {}
proc X509::subject {c} { return "CN=$::cn,O=aplab" }
proc log {args} {}
rename clock _clock
proc clock {args} { return $::now }
proc table {op args} {
  if {[lindex $args 0] eq "-subtable"} { set st [lindex $args 1] ; set args [lrange $args 2 end] } else { set st "" }
  set k "$st/[lindex $args 0]"
  if {$op eq "incr"} { if {[dict exists $::tbl $k]} { dict incr ::tbl $k } else { dict set ::tbl $k 1 } ; return [dict get $::tbl $k] }
  return 120
}
proc fire {name} { if {[info exists ::ev($name)]} { catch {uplevel #0 $::ev($name)} } }
proc req {cn method hdrs payload} {
  foreach v {responded collected released ident} { catch {unset ::$v} }
  array unset ::hdr ; array set ::hdr $hdrs
  set ::cn $cn ; set ::_verb $method ; set ::payload $payload
  fire CLIENT_ACCEPTED ; fire CLIENTSSL_CLIENTCERT ; fire HTTP_REQUEST
  if {![info exists ::responded] && [info exists ::collected]} { fire HTTP_REQUEST_DATA }
  if {[info exists ::responded]} { return $::responded }
  if {[info exists ::collected] && ![info exists ::released]} { return held }
  return pass
}
"""


def run(cases: list[tuple], now: int = 1_800_000_000, rate: int = 5) -> list[str]:
    from autopilot.packages import irule_mcp_policy
    rule = irule_mcp_policy({"agent-b": ["get_alert", "score_transaction"], "ap-validator": ["model_info"]}, rate)
    lines = [HARNESS, rule, f"set now {now}"]
    for c in cases:
        if c[0] == "now":
            lines.append(f"set now {c[1]}")
            continue
        cn, method, hdrs, payload = c
        flat = " ".join(f"{{{k}}} {{{v}}}" for k, v in hdrs.items())
        lines.append(f"puts [req {{{cn}}} {{{method}}} {{{flat}}} {{{payload}}}]")
    out = subprocess.run([TCLSH], input="\n".join(lines), capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


def legacy(body: str, cn="agent-b", cl: str | None = None) -> tuple:
    return (cn, "POST", {"Content-Length": str(len(body)) if cl is None else cl}, body)


def call(tool: str, cn="agent-b") -> tuple:
    """A 2026-07-28 request: the header path (the server enforces header == body for this protocol)."""
    return (cn, "POST", {"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": tool, "Content-Length": "10"}, "{}")


def j(method: str, **params) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def test_identity_required_and_unknown_identity_denied():
    assert run([call("get_alert", cn=""), call("get_alert", cn="intruder")]) == ["401", "403"]


def test_unknown_and_rate_limit_logs_are_bounded_and_before_responses():
    from autopilot.packages import irule_mcp_policy

    rule = irule_mcp_policy({"ap-validator": ["model_info"]}, 120)
    unknown = rule.index("branch=unknown_identity status=403")
    unknown_response = rule.index('HTTP::respond 403 content "unknown agent identity"', unknown)
    rate = rule.index("branch=rate_limit status=429")
    rate_response = rule.index('HTTP::respond 429 content "rate limit exceeded"', rate)

    assert unknown < unknown_response
    assert rate < rate_response
    assert "set log_ident [string range $ident 0 63]" in rule
    assert "regsub -all {[^A-Za-z0-9_.:-]} $log_ident _ log_ident" in rule
    assert "counter=not-counted" in rule
    assert "counter=$n branch=rate_limit status=429" in rule
    assert "request body" not in rule
    assert "private key" not in rule


def test_header_path_tool_authorisation():
    assert run([call("score_transaction"), call("freeze_account"), call("model_info", cn="ap-validator"),
                call("score_transaction", cn="ap-validator")]) == ["pass", "403", "pass", "403"]


def test_legacy_body_inspection_fails_closed():
    res = run([
        legacy(j("tools/call", name="get_alert", arguments={})),                                   # allowed
        legacy(j("tools/call", name="freeze_account", arguments={})),                              # denied
        legacy('{"jsonrpc":"2.0","id":1,"method":"tools\\/call","params":{"name":"freeze_account"}}'),  # escaped method name
        legacy('{"params":{"_meta":{"x":{"name":"get_alert"}},"name":"freeze_account"},"method":"tools/call","id":1}'),  # 2 names: ambiguous
        legacy("[" + j("tools/call", name="freeze_account") + "]"),                               # batch
        legacy(j("tools/call", name="get_alert"), cl=""),                                          # chunked / no Content-Length
        legacy(j("tools/call", name="get_alert"), cl="70000"),                                     # oversized
        legacy(j("initialize", clientInfo={"name": "x"})),                                         # session setup allowed
        legacy(j("resources/read", uri="s3://x")),                                                 # method outside allow-list
    ], rate=1000)
    assert res == ["pass", "403", "403", "400", "400", "411", "413", "pass", "403"]


def test_rate_limit_per_calendar_minute_never_locks_out_busy_identity():
    t = 1_800_000_000 - (1_800_000_000 % 60)
    cases = [call("get_alert") for _ in range(6)] + [("now", t + 59), call("get_alert"), ("now", t + 60)] + \
            [call("get_alert") for _ in range(5)] + [("now", t + 125), call("get_alert")]
    res = run(cases, now=t)
    assert res[:6] == ["pass"] * 5 + ["429"]          # 6th request in the minute is limited
    assert res[6] == "429"                             # still the same minute
    assert res[7:12] == ["pass"] * 5                   # new minute: full allowance again (old counter did not stick)
    assert res[12] == "pass"


def test_unsafe_names_rejected_at_generation():
    from autopilot.packages import irule_mcp_policy
    with pytest.raises(ValueError):
        irule_mcp_policy({"agent-b": ["x} ; HTTP::release ; {"]}, 10)


# ------------------------------------------------------------------ B1 (doc 34): forged / missing / mismatched headers
def legacy_h(body: str, hdrs: dict, cn="agent-b") -> tuple:
    return (cn, "POST", {"Content-Length": str(len(body)), **hdrs}, body)


FREEZE = j("tools/call", name="freeze_account", arguments={"account_id": "ACC-1", "reason": "x"})
ALERT = j("tools/call", name="get_alert", arguments={"alert_id": "ALERT-9000"})


def test_b1_decoy_headers_cannot_skip_legacy_body_inspection():
    res = run([
        legacy_h(FREEZE, {"Mcp-Method": "tools/list"}),                                             # decoy method
        legacy_h(FREEZE, {"Mcp-Method": "ping"}),
        legacy_h(FREEZE, {"Mcp-Method": "tools/call", "Mcp-Name": "get_alert"}),                     # decoy allowed name
        legacy_h(FREEZE, {"Mcp-Method": "tools/list", "Mcp-Protocol-Version": "2025-11-25"}),        # legacy version + decoy
        legacy_h(FREEZE, {"Mcp-Method": "tools/list", "Mcp-Protocol-Version": "2026-07-28 "}),       # not exactly 2026-07-28
        legacy_h(ALERT, {"Mcp-Method": "tools/call", "Mcp-Name": "freeze_account"}),                 # body decides (allowed)
    ], rate=1000)
    assert res == ["403", "403", "403", "403", "403", "pass"]


def test_b1_2026_requests_require_and_restrict_the_method_header():
    v = {"Mcp-Protocol-Version": "2026-07-28", "Content-Length": "10"}
    res = run([
        ("agent-b", "POST", dict(v), "{}"),                                                          # missing Mcp-Method
        ("agent-b", "POST", {**v, "Mcp-Method": "resources/read"}, "{}"),                            # method outside list
        ("agent-b", "POST", {**v, "Mcp-Method": "tools/call"}, "{}"),                                # missing Mcp-Name
        ("agent-b", "POST", {**v, "Mcp-Method": "tools/call", "Mcp-Name": "freeze_account"}, "{}"),  # disallowed tool
        ("agent-b", "POST", {**v, "Mcp-Method": "server/discover"}, "{}"),
        ("agent-b", "POST", {**v, "Mcp-Method": "tools/list"}, "{}"),
        # header names an allowed tool, body another: forwarded by the iRule, rejected by the MCP server (-32020) — see
        # test_security_header_mismatch.py, which runs this against the real server
        ("agent-b", "POST", {**v, "Mcp-Method": "tools/call", "Mcp-Name": "get_alert"}, FREEZE),
    ], rate=1000)
    assert res == ["400", "403", "403", "403", "pass", "pass", "pass"]


def test_b1_tool_must_be_identified_unambiguously_and_bodies_well_formed():
    res = run([
        legacy(j("tools/call", name="get_alert", arguments={"name": "get_alert"})),                 # second "name" key
        legacy(j("tools/call", arguments={})),                                                      # no tool name
        legacy('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"n\\u0061me":"get_alert"}}'),  # escaped key
        legacy('{"jsonrpc":"2.0","id":1,"params":{"name":"get_alert"}}'),                            # no method
        legacy('{"jsonrpc":"2.0","method":"tools/call","method":"ping","params":{"name":"get_alert"}}'),  # two methods
        legacy("not json at all"),                                                                  # malformed
        legacy(""),                                                                                 # empty
        ("agent-b", "GET", {}, ""), ("agent-b", "DELETE", {}, ""),                                  # session stream / end
    ], rate=1000)
    assert res == ["400", "400", "400", "400", "400", "400", "400", "pass", "pass"]


# ------------------------------------------------------------------ real recorded traffic through the real iRule
REAL_HARNESS_REQ = r"""
proc reqb {cn method hdrshex payloadhex} {
  set hdrs [encoding convertfrom utf-8 [binary format H* $hdrshex]]
  return [req $cn $method $hdrs [encoding convertfrom utf-8 [binary format H* $payloadhex]]]
}
"""


def replay(path: str, ident: str) -> list[str]:
    import pathlib
    from autopilot.packages import irule_mcp_policy
    allow = {"agent-b": ["get_account_profile", "get_alert", "get_case_document", "get_recent_transactions", "score_transaction",
                         "search_fraud_patterns"], "ap-validator": ["model_info", "score_transaction"]}      # = live security package
    reqs = [json.loads(x) for x in (pathlib.Path(__file__).parent / "fixtures" / "security" / path).read_text().splitlines() if x.strip()]
    b64 = lambda s: s.encode().hex() or "\"\""                                                   # noqa: E731  (hex: Tcl 8.5 compatible)
    lines = [HARNESS, REAL_HARNESS_REQ, irule_mcp_policy(allow, 10**6), "set now 1800000000"]
    for q in reqs:
        hdrs = {k.title(): v for k, v in q["headers"].items() if k in ("content-length", "mcp-method", "mcp-name", "mcp-protocol-version")}
        flat = " ".join(f"{{{k}}} {{{v}}}" for k, v in hdrs.items())
        lines.append(f"puts [reqb {{{ident}}} {{{q['method']}}} {b64(flat)} {b64(q['body'])}]")
    out = subprocess.run([TCLSH], input="\n".join(lines), capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


def test_real_agent_b_traffic_all_11_scenarios_passes_the_corrected_policy():
    res = replay("agent-b-requests.jsonl", "agent-b")
    assert len(res) == 201 and set(res) == {"pass"}, sorted(set(res))


def test_real_validator_gate_traffic_passes_except_the_intended_deny():
    res = replay("validator-requests.jsonl", "ap-validator")
    assert len(res) == 97 and res.count("403") == 1 and res.count("pass") == 96
