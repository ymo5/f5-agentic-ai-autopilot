"""Regression for the AI Security gate failures of deployment 2e18295c (2026-10-17): on the risk VS the policy iRule's
HTTP::respond (403 unknown identity, 429 rate limit) was followed by irule_mcp_persist reading an HTTP header, which BIG-IP
rejects after a response ("TCL error: ... irule_mcp_persist <HTTP_REQUEST> - Can't call after responding - ERR_NOT_SUPPORTED",
LTM log 11:20:23Z / 11:21:03Z); the Tcl error aborted the connection and the client saw ReadError instead of 403/429.

The harness chains the ACTUAL generated iRules like TMM: every attached rule's handler runs in order, `return` ends only the
current rule's handler, HTTP commands after HTTP::respond raise ERR_NOT_SUPPORTED, and a Tcl error aborts the connection
(the queued response is discarded)."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from autopilot.packages import IRULE_MCP_PERSIST, irule_mcp_policy

TCLSH = shutil.which("tclsh")
pytestmark = pytest.mark.skipif(not TCLSH, reason="tclsh not available")

GUARD = "  if { [HTTP::has_responded] } { return }\n"
ALLOW = {"agent-b": ["get_account_profile", "get_alert", "get_case_document", "get_recent_transactions", "score_transaction",
                     "search_fraud_patterns"], "ap-validator": ["model_info", "score_transaction"]}      # = live security package

HARNESS = r'''
set ::rules {}; set ::cur ""
proc rule {name body} { set ::cur $name; lappend ::rules $name; uplevel #0 $body }
proc when {ev body} { set ::ev($::cur,$ev) $body }
namespace eval HTTP {}
proc HTTP::header {op name args} {
  if {[info exists ::responded]} { error "Can't call after responding - ERR_NOT_SUPPORTED" }
  if {$op eq "value"} { if {[info exists ::hdr($name)]} { return $::hdr($name) } ; return "" }
  if {$op eq "replace"} { set ::hdr($name) [lindex $args 0] }
}
proc HTTP::respond {code args} {
  if {[info exists ::responded]} { error "Can't call after responding - ERR_NOT_SUPPORTED" }
  set ::responded $code ; set ::resp_args $args
}
proc HTTP::has_responded {} { return [info exists ::responded] }
proc HTTP::method {} { return POST }
proc HTTP::collect {n} { set ::collected $n }
proc HTTP::payload {} { return $::payload }
proc HTTP::release {} {}
namespace eval SSL {} ; proc SSL::cert {a args} { if {$a eq "count"} { return [expr {$::cn ne ""}] } ; return c }
namespace eval X509 {} ; proc X509::subject {c} { return "CN=$::cn" }
proc log {args} {}
proc persist {args} { lappend ::persist_calls $args }
rename clock _clock ; proc clock {args} { return 1800000000 }
proc table {op args} { if {$op eq "incr"} { return $::counter } ; return 120 }
proc fire {ev} {
  foreach r $::rules {
    if {[info exists ::ev($r,$ev)]} {
      if {[catch {uplevel #0 $::ev($r,$ev)} e] == 1} { return "RESET" }
    }
  }
  return ok
}
proc req {cn counter hdrs {payload ""}} {
  foreach v {responded resp_args collected persist_calls} { catch {unset ::$v} }
  array unset ::hdr ; array set ::hdr $hdrs
  set ::cn $cn ; set ::counter $counter ; set ::payload $payload ; set ::persist_calls {}
  fire CLIENT_ACCEPTED ; fire CLIENTSSL_CLIENTCERT
  if {[fire HTTP_REQUEST] eq "RESET"} { return "RESET" }
  if {![info exists ::responded] && [info exists ::collected]} { if {[fire HTTP_REQUEST_DATA] eq "RESET"} { return "RESET" } }
  if {[info exists ::responded]} { return "HTTP:$::responded:[join $::resp_args |]" }
  return "FORWARD:[join $::persist_calls |]"
}
proc resp {hdrs} {
  set ::persist_calls {} ; catch {unset ::responded} ; array unset ::hdr ; array set ::hdr $hdrs
  if {[fire HTTP_RESPONSE] eq "RESET"} { return "RESET" }
  return "RESPONSE:[join $::persist_calls |]"
}
'''

H2026 = {"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Content-Length": "10"}


def chain(persist: str, cases: list[tuple]) -> list[str]:
    """cases: ("req", cn, counter, headers[, payload]) or ("resp", headers). Returns one outcome per case."""
    rules = [("irule_mcp_policy", irule_mcp_policy(ALLOW, 120)), ("irule_mcp_persist", persist)]
    lines = [HARNESS] + [f"rule {n} {{{b}}}" for n, b in rules]
    for c in cases:
        flat = lambda h: " ".join(f"{{{k}}} {{{v}}}" for k, v in h.items())   # noqa: E731
        if c[0] == "req":
            payload = c[4] if len(c) > 4 else ""
            lines.append(f"puts [req {{{c[1]}}} {c[2]} {{{flat(c[3])}}} {{{payload}}}]")
        else:
            lines.append(f"puts [resp {{{flat(c[1])}}}]")
    out = subprocess.run([TCLSH], input="\n".join(lines), capture_output=True, text=True, timeout=30)
    assert out.returncode == 0 and not out.stderr, out.stderr
    return out.stdout.splitlines()


def unguarded() -> str:
    assert GUARD in IRULE_MCP_PERSIST
    return IRULE_MCP_PERSIST.replace(GUARD, "", 1)


def test_generated_persist_rule_is_guarded():
    assert IRULE_MCP_PERSIST.splitlines()[3:5] == ["when HTTP_REQUEST {", GUARD.rstrip("\n")]


def test_unknown_identity_delivers_403_through_policy_and_persist_chain():
    assert chain(IRULE_MCP_PERSIST, [("req", "ap-unauthorized", 1, {**H2026, "Mcp-Name": "model_info"})]) == \
        ["HTTP:403:content|unknown agent identity"]


def test_rate_limit_delivers_429_with_retry_after_through_the_chain():
    res = chain(IRULE_MCP_PERSIST, [("req", "ap-validator", 120, {**H2026, "Mcp-Name": "model_info"}),
                                    ("req", "ap-validator", 121, {**H2026, "Mcp-Name": "model_info"})])
    assert res[0].startswith("FORWARD")
    assert res[1] == "HTTP:429:content|rate limit exceeded|Retry-After|60"


def test_other_policy_refusals_on_the_risk_chain_are_delivered():
    res = chain(IRULE_MCP_PERSIST, [
        ("req", "ap-validator", 1, {**H2026, "Mcp-Name": "freeze_account"}),                     # forbidden tool (header path)
        ("req", "ap-validator", 1, {"Mcp-Protocol-Version": "2026-07-28", "Content-Length": "10"}),  # missing Mcp-Method
        ("req", "", 1, {**H2026, "Mcp-Name": "model_info"}),                                      # no client certificate
        ("req", "agent-b", 1, {"Content-Length": "60"},                                          # legacy forbidden (REQUEST_DATA)
         '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"freeze_account"}}'),
    ])
    assert res == ["HTTP:403:content|tool not permitted for ap-validator", "HTTP:400:content|Mcp-Method header required",
                   "HTTP:401:content|client certificate required", "HTTP:403:content|tool not permitted for agent-b"]


def test_allowed_requests_are_forwarded_and_session_persistence_still_works():
    sid = "8a3f0c2d9e7b4c1a"
    res = chain(IRULE_MCP_PERSIST, [
        ("req", "ap-validator", 5, {**H2026, "Mcp-Name": "model_info"}),                          # stateless: no persistence
        ("req", "agent-b", 5, {"Content-Length": "62", "Mcp-Session-Id": sid},                     # legacy session request
         '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_alert"}}'),
        ("resp", {"Mcp-Session-Id": sid}),                                                       # initialize response
    ])
    assert res == ["FORWARD:", f"FORWARD:uie {sid} 1800", f"RESPONSE:add uie {sid} 1800"]


def test_unguarded_rule_reproduces_the_live_resets():
    """The pre-fix persist rule (as deployed in 2e18295c) loses both responses, exactly as the LTM log showed."""
    res = chain(unguarded(), [("req", "ap-unauthorized", 1, {**H2026, "Mcp-Name": "model_info"}),
                              ("req", "ap-validator", 121, {**H2026, "Mcp-Name": "model_info"}),
                              ("req", "ap-validator", 5, {**H2026, "Mcp-Name": "model_info"})])
    assert res == ["RESET", "RESET", "FORWARD:"]
