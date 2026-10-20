"""Before/after comparison and the customer reports (executive summary, technical report, evidence bundle).

All three reports and the comparison UI are built from ONE comparison model (compare()), so they cannot disagree.

A finding of the 'before' assessment is reported "resolved (validated)" only when ALL of these hold:
  1. the 'after' discovery no longer raises it (same rule on the same affected assets);
  2. a successful deployment of the package that addresses it is linked to the comparison (it was in place when the 'after'
     discovery ran) AND a deployment of that package kind is in place now (verified effective state);
  3. its proving tests passed in the latest qualifying validation evidence of the in-place deployment
     (validation_evidence.current: runs/gates since that deployment, in a profile that exercises it; window-locked checks are
     "not run", never failures; runs invalidated by the validator client defect are ignored).
When the 'after' discovery predates the in-place deployment that addresses a finding, the finding is still observed in that
discovery: if its proving tests pass it is reported "awaiting rediscovery — enforcement validated", never "resolved".
Failed, refused or rolled-back deployments never count as remediation.
"""
from __future__ import annotations

import html
import json
import time

UTC = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else "—"  # noqa: E731

from . import catalog, explorer, identity, validation_evidence, verification


def _findings(store, aid: str) -> list[dict]:
    keys = {r["id"]: r["key"] for r in store.db.execute("SELECT id, key FROM asset WHERE assessment_id=?", (aid,))}
    out = []
    for r in store.db.execute("SELECT * FROM finding WHERE assessment_id=?", (aid,)):
        f = dict(r)
        f["asset_keys"] = sorted(keys.get(x, x) for x in json.loads(f["asset_ids"]))
        f["identity"] = f"{f['rule_id']}|{','.join(f['asset_keys'])}"
        f.update({k: v for k, v in catalog.meta(f["rule_id"], f["title"]).items() if k in ("issue", "class", "class_label", "package", "not_addressed")})
        out.append(f)
    return out


def linked_deployments(store, before: str) -> list[dict]:
    created = store.db.execute("SELECT created FROM assessment WHERE id=?", (before,)).fetchone()
    t0 = created["created"] if created else 0
    rows = store.db.execute("SELECT d.*, p.kind, p.title FROM deployment d LEFT JOIN package p ON p.id=d.package_id "
                            "WHERE d.started >= ? ORDER BY d.started", (t0,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        steps = json.loads(d.pop("steps") or "[]")
        gate = next((s for s in steps if s["step"].startswith("gate.validate")), None)
        d["gate"] = gate and {"status": gate["status"], "passed": (gate.get("detail") or {}).get("passed") if isinstance(gate.get("detail"), dict) else None}
        d.pop("previous_state", None)
        out.append(d)
    place = {x["id"] for x in verification.protection_from_store(store)["in_place"]}
    for d in out:                       # effective state, not the historical status alone
        d["in_place"] = d["id"] in place
        d["now"] = ("in place" if d["in_place"] else "historical — " + ("succeeded, since removed (rollback / Reset Demo / replaced)"
                    if d["status"] == "succeeded" else d["status"]))
    return out


def _matches(f: dict, others: list[dict]) -> bool:
    """Same rule on (at least) the same affected assets — robust to a later discovery seeing more endpoints of one service."""
    keys = set(f["asset_keys"])
    return any(o["rule_id"] == f["rule_id"] and keys <= set(o["asset_keys"]) for o in others)


def compare(store, before: str, after: str) -> dict:
    fb, fa = _findings(store, before), _findings(store, after)
    comp = explorer.comparability(store, before, after)
    disc_at = comp.get("after_discovered_at")
    linked_kinds = {d.get("kind") or "delivery" for d in comp.get("linked_successful_deployments") or []}
    place = validation_evidence.in_place(store)
    all_runs = validation_evidence.runs(store)
    deps = linked_deployments(store, before)
    rows = []
    for f in fb:
        need = catalog.tests_for(f["rule_id"], f["title"])
        kind = f.get("package")
        dep = place.get(kind) if kind else None
        cur = validation_evidence.current(store, kind, set(need), all_runs, place) if dep and need else {}
        tests = [{"test": t, **cur[t]} if t in cur else {"test": t, "result": "no current result"} for t in need]
        passed = [t for t in need if (cur.get(t) or {}).get("result") == "pass"]
        failed = [t for t in need if (cur.get(t) or {}).get("result") == "fail"]
        all_pass = bool(need) and len(passed) == len(need)
        if _matches(f, fa):
            if not kind:
                outcome = "remaining — not addressed by any package"
            elif dep and disc_at and (dep["started"] or 0) > disc_at and all_pass:
                outcome = "awaiting rediscovery — enforcement validated after this discovery"
            elif dep and disc_at and (dep["started"] or 0) > disc_at:
                outcome = "remaining — deployed after this discovery; " + (f"latest validation failed ({', '.join(failed)})" if failed
                                                                          else "awaiting validation evidence")
            else:
                outcome = "remaining"
        elif not kind:
            outcome = "not raised — no package addresses it (unverified change)"
        elif not dep:
            outcome = "not raised — no deployment in place addresses it (not claimed as remediated)"
        elif kind not in linked_kinds:
            outcome = "not raised — no linked deployment explains the change (not claimed as remediated)"
        elif failed:
            outcome = f"not raised — latest validation failed ({', '.join(failed)})"
        elif not all_pass:
            outcome = "not raised — awaiting validation evidence"
        else:
            outcome = "resolved (validated)"
        rows.append({**f, "outcome": outcome, "proven_by": need, "tests_passed": passed,
                     "evidence": {"after_discovered_at": disc_at, "deployment_in_place": dep and {"id": dep["id"], "kind": kind, "started": dep["started"]},
                                  "tests": tests}})
    cnt = lambda aid, t: store.db.execute(f"SELECT COUNT(*) FROM {t} WHERE assessment_id=?", (aid,)).fetchone()[0]  # noqa: E731
    out = lambda pre: [r for r in rows if r["outcome"].startswith(pre)]  # noqa: E731
    return {"before": before, "after": after, "findings": rows, "deployments": deps, "comparability": comp,
            # findings present only in 'after' usually reflect wider discovery coverage, never "deterioration"
            "new_in_after": [{**f, "interpretation": "newly observed — reflects discovery coverage or a new condition; not evidence that "
                                                     "security deteriorated"} for f in fa if not any(_matches(b, [f]) for b in fb)],
            "summary": {"resolved": len(out("resolved")), "awaiting_rediscovery": len(out("awaiting rediscovery")),
                        "remaining": len(out("remaining")), "not_addressed": len(out("remaining — not addressed")),
                        "unverified": len(out("not raised")), "findings_before": len(rows),
                        "risk_types_before": len({r["rule_id"] for r in rows}),
                        "counting": "findings = one rule on one affected service/endpoint set; risk types = distinct rules"},
            "counts": {"before": {"assets": cnt(before, "asset"), "relationships": cnt(before, "rel"), "findings": len(fb)},
                       "after": {"assets": cnt(after, "asset"), "relationships": cnt(after, "rel"), "findings": len(fa)}},
            "topology": topology_changes(store, before, after), "coverage": {"before": coverage(store, before), "after": coverage(store, after),
                                                                            "definitions": COVERAGE_DEFINITIONS},
            "ingest_windows": {"before": ingest_window(store, before), "after": ingest_window(store, after)},
            "performance": performance(store, before, after),
            "validation_performance": validation_performance(store, before, after, place, all_runs),
            "fraud_runs": fraud_history(store, since=(comp.get("before") or {}).get("created"), place=place)}


def ingest_window(store, aid: str) -> dict | None:
    """The trace window behind an assessment's observed paths and latencies, as recorded by its latest Ingest."""
    r = store.db.execute("SELECT raw, collected_at FROM evidence WHERE assessment_id=? AND source='ingest' ORDER BY collected_at DESC LIMIT 1",
                         (aid,)).fetchone()
    if not r:
        return None
    w = (json.loads(r["raw"] or "{}") or {}).get("window") or {}
    bounded = bool(w.get("start") or w.get("since"))
    return {"collected_at": r["collected_at"], "start": w.get("start") or w.get("since"), "end": w.get("end") or r["collected_at"],
            "reason": w.get("reason"), "truncated_services": w.get("truncated_services") or [], "bounded": bounded,
            "note": None if bounded else ("collected before the window fix: Jaeger ignored the 'lookback' parameter, so this ingest may "
                                         "include traces older than its stated window (doc 38)")}


def _paths(store, aid: str) -> dict:
    by = {a["id"]: a for a in store.assets(aid)}
    out = {}
    for r in store.rels(aid):
        if not r["kind"].startswith("calls_"):
            continue
        s, d = by.get(r["src"], {}), by.get(r["dst"], {})
        key = (s.get("attrs", {}).get("otel_service") or s.get("name"), d.get("name"), r["kind"][6:])
        ing = [c for c in r["claims"] if c["source"] == "ingest"]
        out[key] = {"path": r["observed_path"], "target": d.get("key", "").split(":", 1)[-1],
                    "latency_ms": ing[-1]["attrs"].get("latency_ms") if ing else None, "calls": ing[-1]["attrs"].get("calls") if ing else None}
    return out


def topology_changes(store, before: str, after: str) -> list[dict]:
    pb, pa = _paths(store, before), _paths(store, after)
    out = []
    for k in sorted(set(pb) | set(pa), key=str):
        b, a = pb.get(k), pa.get(k)
        out.append({"from": k[0], "to": k[1], "protocol": k[2], "before": b and b["path"], "after": a and a["path"],
                    "before_target": b and b["target"], "after_target": a and a["target"],
                    "change": "unchanged" if b and a and b["path"] == a["path"] else "new" if not b else "gone" if not a else f"{b['path']} → {a['path']}"})
    return out


COVERAGE_DEFINITIONS = {
    "endpoints": "A2A/MCP server endpoints (address:port) discovered in the assessment that are members of a BIG-IP pool used by an "
                 "observed virtual server. Counts listeners, so one service with a front-network and a back-network listener counts twice.",
    "services": "Canonical AI services (the Overview's 'protected' question: agents, MCP servers, LLM endpoints) with at least one "
                "endpoint in such a pool. A client-only agent has no listener to front.",
    "scope": "Both are Observe (configuration) facts at discovery time. Neither measures AI Security enforcement — that is reported "
             "by the validation results.",
}


def coverage(store, aid: str) -> dict:
    assets = store.assets(aid)
    vs = [a for a in assets if a["kind"] == "bigip_virtual"]
    used_pools = {v["attrs"].get("pool") for v in vs}
    members = {a["key"].split(":", 1)[1] for a in assets if a["attrs"].get("bigip_pool_member_of") in used_pools}
    ai = [a for a in assets if a["kind"] in ("a2a_agent", "mcp_server") and a["key"].startswith("ep:")]
    fronted = [a for a in ai if a["key"].split(":", 1)[1] in members]
    svcs = []
    try:
        for s in identity.reconcile(store, aid)["services"]:
            if s["kind"] in ("a2a_agent", "mcp_server", "ai_agent", "llm_endpoint"):
                addrs = {e["address"] for e in s["endpoints"]}
                svcs.append({"name": s["name"], "kind": s["kind"], "fronted": bool(addrs & members), "listens": bool(addrs)})
    except Exception:       # identity needs ingest evidence; an assessment without it simply has no service view
        svcs = []
    return {"virtual_servers": len(vs), "pools": sum(a["kind"] == "bigip_pool" for a in assets),
            "ai_endpoints": len(ai), "ai_endpoints_behind_bigip": len(fronted),
            "percent": round(100 * len(fronted) / len(ai)) if ai else 0,
            "endpoints": sorted([{"address": a["key"].split(":", 1)[1], "name": a["name"], "kind": a["kind"],
                                  "fronted": a in fronted} for a in ai], key=lambda x: x["address"]),
            "services": {"total": len(svcs), "fronted": sum(x["fronted"] for x in svcs), "items": svcs}}


def performance(store, before: str, after: str) -> list[dict]:
    pb, pa = _paths(store, before), _paths(store, after)
    out = []
    for k in sorted(set(pb) & set(pa), key=str):
        lb, la = (pb[k]["latency_ms"] or {}), (pa[k]["latency_ms"] or {})
        if lb or la:
            out.append({"from": k[0], "to": k[1], "protocol": k[2], "p50_before": lb.get("p50"), "p50_after": la.get("p50"),
                        "p95_before": lb.get("p95"), "p95_after": la.get("p95")})
    return out


def security_results(store, aid: str) -> list[dict]:
    """Enforcement results of the AI Security deployment that is in place now (verified), from the latest valid after-security run
    (manual run or the deployment's gate) that started on/after it. Delivery-profile security.* checks (exposure), removed/reset
    security deployments and runs invalidated by the validator client defect never count; window-locked checks are 'not_run'."""
    sec = validation_evidence.in_place(store).get("security")
    if not sec:
        return []
    for r in validation_evidence.runs(store):
        if r["profile"] == "after-security" and r["started"] >= (sec["started"] or 0) and not (r["note"] or "").startswith("invalid run"):
            return [{**t, "result": validation_evidence.effective(t), "run_id": r["id"], "at": r["started"], "source": r["source"]}
                    for t in r["results"] if t["test"].startswith("security.")]
    return []


def _comparability_banner(cmp_: dict) -> str:
    c = cmp_.get("comparability") or {}
    if not c:
        return ""
    col = {"verified": "#1a7f37", "exploratory": "#9a6700", "invalid": "#cf222e"}.get(c["status"], "#57606a")
    return (f"<div style='border:2px solid {col};border-radius:8px;padding:10px 14px;margin:12px 0'><b style='color:{col}'>"
            f"{html.escape(c['label'])}</b><ul>" + "".join(f"<li>{html.escape(r)}</li>" for r in c["reasons"]) + "</ul>"
            + ("" if c["claims_allowed"] else "<b>No F5 benefit is claimed from this comparison.</b>") + "</div>")


def html_report(store, aid: str, before: str | None) -> str:
    e = html.escape
    a = store.db.execute("SELECT * FROM assessment WHERE id=?", (aid,)).fetchone()
    fs = _findings(store, aid)
    vals = [dict(r) | {"results": json.loads(r["results"])} for r in store.db.execute(
        "SELECT * FROM validation_run WHERE assessment_id=? ORDER BY started", (aid,))]
    cmp_ = compare(store, before, aid) if before else None
    css = ("body{font-family:system-ui;margin:2rem auto;max-width:1150px;color:#1b1f24}table{border-collapse:collapse;width:100%;margin:6px 0 18px}"
           "td,th{border-bottom:1px solid #d0d7de;padding:5px;font-size:13px;vertical-align:top;text-align:left}code{font-size:11px}"
           ".k{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;border:1px solid #888}.ok{color:#1a7f37;border-color:#1a7f37}"
           ".bad{color:#cf222e;border-color:#cf222e}.warn{color:#9a6700;border-color:#9a6700}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}"
           ".tile{border:1px solid #d0d7de;border-radius:8px;padding:10px}.tile b{font-size:22px;display:block}")

    def k(v, cls=""):
        return f"<span class='k {cls}'>{e(str(v))}</span>"
    parts = [f"<!doctype html><html><head><meta charset=utf-8><title>AI Delivery & Security Assessment</title><style>{css}</style></head><body>",
             f"<h1>AI Delivery &amp; Security Assessment</h1><p>Assessment <b>{e(a['name'])}</b> ({e(aid)}) — generated "
             f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} by F5 Agentic AI Autopilot. Every finding cites collected evidence; "
             "customer assertions are reported only where corroborated or contradicted; a finding is shown as resolved only with a "
             "successful deployment AND passing validation tests.</p>"]
    if cmp_:
        parts.append(_comparability_banner(cmp_))
        sm, cb, ca = cmp_["summary"], cmp_["coverage"]["before"], cmp_["coverage"]["after"]
        parts.append(f"<div class='grid'><div class='tile'><b>{sm['resolved']}</b>resolved (validated)</div>"
                     f"<div class='tile'><b>{sm['awaiting_rediscovery']}</b>enforcement validated — awaiting rediscovery</div>"
                     f"<div class='tile'><b>{sm['remaining']}</b>remaining ({sm['not_addressed']} not addressed by any package)</div>"
                     f"<div class='tile'><b>{sm['unverified']}</b>not raised, not claimed</div><div class='tile'><b>{_cov_text(cb)} → {_cov_text(ca)}</b>"
                     f"A2A/MCP endpoints fronted by BIG-IP ({cb['percent']}% → {ca['percent']}%; {cb['virtual_servers']} → {ca['virtual_servers']} virtual servers)</div></div>"
                     f"<p><small>{e(COVERAGE_DEFINITIONS['endpoints'])} Services fronted (Overview definition): {ca['services']['fronted']} of "
                     f"{ca['services']['total']}. Unfronted endpoints after: {e(', '.join(x['address'] for x in ca['endpoints'] if not x['fronted']) or 'none')}. "
                     f"{e(COVERAGE_DEFINITIONS['scope'])}</small></p>")
        iw = cmp_["ingest_windows"]
        parts.append("<p><small>Trace windows behind observed paths and latencies — " + "; ".join(
            f"{side}: {UTC((w or {}).get('start'))} → {UTC((w or {}).get('end'))}" + (f" ({e(w['note'])})" if w and w.get("note") else "")
            for side, w in iw.items()) + "</small></p>")
        parts.append("<h2>Linked deployments</h2><table><tr><th>deployment</th><th>package</th><th>status</th><th>now</th><th>approved package hash</th><th>by</th><th>validation gate</th></tr>" +
                     "".join(f"<tr><td><code>{e(d['id'])}</code></td><td>{e(d.get('title') or d['package_id'])}</td><td>{k(d['status'], 'ok' if d['status'] == 'succeeded' else 'bad')}</td>"
                             f"<td>{k(d.get('now') or '—', 'ok' if d.get('in_place') else 'warn')}</td><td><code>{e(d['package_hash'][:16])}…</code></td><td>{e(d['requested_by'])}</td><td>{e((d['gate'] or {}).get('status') or '—')}</td></tr>"
                             for d in cmp_["deployments"]) + "</table>" if cmp_["deployments"] else "<h2>Linked deployments</h2><p>None — no remediation is claimed.</p>")
        parts.append("<h2>Findings: before → after</h2><table><tr><th>finding</th><th>class</th><th>outcome</th><th>proving tests (current result, time)</th></tr>" +
                     "".join(f"<tr><td>{e(f['rule_id'])} {e(f['title'])}</td><td>{e(f.get('class_label') or '')}</td>"
                             f"<td>{k(f['outcome'], 'ok' if f['outcome'].startswith('resolved') else 'bad' if f['outcome'].startswith('remaining') else 'warn')}"
                             f"{'<br><small>' + e(f['not_addressed']) + '</small>' if f.get('not_addressed') and f['outcome'].startswith('remaining') else ''}</td>"
                             f"<td><small>{e('; '.join(t['test'] + ' ' + t['result'] + (' ' + UTC(t['at']) if t.get('at') else '') for t in f['evidence']['tests']) or '—')}</small></td></tr>"
                             for f in cmp_["findings"]) + "</table>")
        parts.append("<h2>Validated topology changes</h2><table><tr><th>from</th><th>to</th><th>protocol</th><th>before</th><th>after</th></tr>" +
                     "".join(f"<tr><td>{e(t['from'] or '')}</td><td>{e(t['to'] or '')}</td><td>{e(t['protocol'])}</td><td>{e(t['before'] or '—')} <small>{e(t['before_target'] or '')}</small></td>"
                             f"<td>{e(t['after'] or '—')} <small>{e(t['after_target'] or '')}</small></td></tr>" for t in cmp_["topology"]) + "</table>")
        if cmp_["performance"]:
            parts.append("<h2>Performance (OpenTelemetry latency, ms)</h2><table><tr><th>path</th><th>p50 before</th><th>p50 after</th><th>p95 before</th><th>p95 after</th></tr>" +
                         "".join(f"<tr><td>{e(p['from'] or '')} → {e(p['to'] or '')} ({e(p['protocol'])})</td><td>{p['p50_before']}</td><td>{p['p50_after']}</td>"
                                 f"<td>{p['p95_before']}</td><td>{p['p95_after']}</td></tr>" for p in cmp_["performance"]) + "</table>")
    if cmp_:
        vp = cmp_["validation_performance"]
        parts.append("<h2>Performance — equivalent validator workload</h2><table><tr><th>state</th><th>run</th><th>MCP p50</th><th>MCP p95</th>"
                     "<th>A2A task</th></tr>" + "".join(
                         f"<tr><td>{e(p['profile'])}</td><td><code>{e(p['run_id'] or 'no run')}</code> {UTC(p['measured_at']) if p['measured_at'] else ''}</td>"
                         f"<td>{_num(p['mcp_p50_ms'], ' ms')}</td><td>{_num(p['mcp_p95_ms'], ' ms')}</td><td>{_num(p['a2a_task_s'], ' s')}</td></tr>"
                         for p in vp["rows"]) + f"</table><p><small>{e(vp['statement'])}</small></p>")
        fh = cmp_["fraud_runs"]
        parts.append(f"<h2>Fraud application runs since {e(fh.get('since_utc') or '—')}</h2>" + ("<table><tr><th>time</th><th>scenario</th><th>infrastructure</th>"
                     "<th>decision</th><th>seconds</th><th>paths</th></tr>" + "".join(
                         f"<tr><td>{e(r['created_utc'])}</td><td>{e(r['scenario'])}</td><td>{e(r['infra_state'])}</td><td>{e(r['decision'] or r['state'])}</td>"
                         f"<td>{r['seconds']}</td><td><code>{e(json.dumps(r['paths'] or {}))}</code></td></tr>" for r in fh["runs"]) + "</table>"
                     if fh["runs"] else "<p>none</p>") + (f"<p><small>{e(fh['note'])}</small></p>" if fh.get("note") else ""))
    sec = security_results(store, aid)
    if sec:
        parts.append("<h2>Security enforcement results</h2><table><tr><th>test</th><th>result</th><th>observed</th></tr>" +
                     "".join(f"<tr><td>{e(t['test'])}</td><td>{k(t['result'], 'ok' if t['result'] == 'pass' else 'bad')}</td><td><code>{e(json.dumps(t['observed'])[:220])}</code></td></tr>"
                             for t in sec) + "</table>")
    parts.append(f"<h2>Current findings ({len(fs)})</h2><table><tr><th>sev</th><th>rule</th><th>class</th><th>finding</th><th>detail</th><th>evidence</th></tr>" +
                 "".join(f"<tr><td>{e(f['severity'])}</td><td>{e(f['rule_id'])}</td><td>{e(f.get('class_label') or '')}</td><td>{e(f['title'])}</td><td>{e(f['detail'])}</td>"
                         f"<td><code>{e(', '.join(json.loads(f['evidence_ids'])))}</code></td></tr>" for f in fs) + "</table>")
    gaps = sorted({(f["rule_id"], f.get("not_addressed")) for f in fs if f.get("not_addressed")})
    if gaps:
        parts.append("<h2>Remaining gaps (no package in this iteration)</h2><ul>" + "".join(f"<li><b>{e(r)}</b> — {e(t)}</li>" for r, t in gaps) + "</ul>")
    vals = annotate_runs(vals)
    parts.append("<h2>Validation runs</h2>" + ("".join(
        f"<h3>{e(v['label'])} · {UTC(v['started'])} — {v['effective']['pass']}/{v['effective']['ran']} pass"
        f"{', ' + str(v['effective']['not_run']) + ' not run (live window required)' if v['effective']['not_run'] else ''}"
        f"{' · superseded by ' + e(v['superseded_by']) if v.get('superseded_by') else ' · current'}</h3>"
        + (f"<p><small>{e(v['note'])}</small></p>" if v.get("note") else "") + "<ul>" +
        "".join(f"<li>{e(validation_evidence.effective(t).upper().replace('_', ' '))} {e(t['test'])}: <code>{e(json.dumps(t['observed'])[:260])}</code></li>"
                for t in v["results"]) + "</ul>"
        for v in vals) or "<p>none</p>"))
    return "".join(parts) + "</body></html>"


def _perf_row(label: str, r: dict | None) -> dict:
    if not r:
        return {"profile": label, "measured": False, "run_id": None, "measured_at": None, "mcp_p50_ms": None, "mcp_p95_ms": None,
                "a2a_task_s": None, "passed": None, "total": None}
    res = {t["test"]: t for t in r["results"]}
    m, a = (res.get("perf.mcp_tool_latency") or {}).get("observed") or {}, (res.get("perf.a2a_investigation") or {}).get("observed") or {}
    eff = [validation_evidence.effective(t) for t in res.values()]
    row = {"profile": label, "run_id": r["id"], "source": r.get("source", "validation run"), "measured_at": r["started"],
           "assessment": r.get("assessment_id"), "mcp_p50_ms": m.get("p50_ms"), "mcp_p95_ms": m.get("p95_ms"), "a2a_task_s": a.get("task_seconds"),
           "passed": eff.count("pass"), "total": len(eff), "not_run": eff.count("not_run")}
    row["measured"] = any(row[k] is not None for k in ("mcp_p50_ms", "mcp_p95_ms", "a2a_task_s"))
    return row


def perf_comparison(store) -> list[dict]:
    """Latest validator workload measurement per profile across assessments (Observe page overview; not a before/after claim)."""
    out = []
    for label in ("before", "after-delivery", "after-security"):
        r = store.db.execute("SELECT id, results, started, assessment_id FROM validation_run WHERE label=? ORDER BY started DESC LIMIT 1", (label,)).fetchone()
        if r:
            out.append(_perf_row(label, {"id": r["id"], "started": r["started"], "assessment_id": r["assessment_id"],
                                         "results": json.loads(r["results"])}))
    return out


def validation_performance(store, before: str, after: str, place: dict | None = None, all_runs: list | None = None) -> dict:
    """Equivalent validator workload for THIS comparison: the 'before' assessment's own baseline run, and for each deployment kind
    in place now its latest valid run/gate since that deployment. A comparison is claimed only when both sides were measured."""
    place = validation_evidence.in_place(store) if place is None else place
    all_runs = validation_evidence.runs(store) if all_runs is None else all_runs
    valid = [r for r in all_runs if not (r["note"] or "").startswith("invalid run")]
    rows = [_perf_row("before", next((r for r in valid if r["profile"] == "before" and r["assessment_id"] == before), None))]
    for kind, label in (("delivery", "after-delivery"), ("security", "after-security")):
        dep = place.get(kind)
        if dep:
            rows.append(_perf_row(label, next((r for r in valid if r["profile"] == label and r["started"] >= (dep["started"] or 0)), None)))
    after_rows = [r for r in rows[1:] if r["measured"]]
    ok = rows[0]["measured"] and bool(after_rows)
    return {"rows": rows, "comparable": ok,
            "statement": ("Before/after measured with the same validator workload." if ok else
                          "No baseline measurement exists for this comparison's 'before' assessment — no before/after performance "
                          "comparison is claimed; the rows show absolute measurements only." if not rows[0]["measured"] else
                          "No measurement exists for the deployed state — no before/after performance comparison is claimed.")}


def fraud_history(store, since: float | None = None, limit: int = 50, place: dict | None = None) -> dict:
    """Fraud application runs in the comparison window (since the 'before' assessment), each with its UTC time and the
    infrastructure state recorded when it ran."""
    place = validation_evidence.in_place(store) if place is None else place
    out = []
    for r in store.db.execute("SELECT id, created, scenario_id, state, seconds, infra_state, trace_id, summary, response FROM fraud_run "
                              "WHERE created >= ? ORDER BY created DESC LIMIT ?", (since or 0, limit)):
        s, resp = json.loads(r["summary"] or "{}"), json.loads(r["response"] or "{}")
        out.append({"id": r["id"], "created": r["created"], "created_utc": UTC(r["created"]), "scenario": r["scenario_id"], "state": r["state"],
                    "seconds": r["seconds"], "infra_state": r["infra_state"] or "unknown", "trace_id": r["trace_id"], "paths": s.get("paths"),
                    "spans": s.get("spans"), "decision": ((resp.get("result") or {}).get("assessment") or {}).get("decision")})
    states = sorted({r["infra_state"] for r in out})
    note = None
    if "security" in place and not any(r["infra_state"] == "security" and r["created"] >= (place["security"]["started"] or 0) for r in out):
        note = ("No fraud scenario has run since AI Security was deployed — these runs do not demonstrate AI Security; run a scenario "
                "to add that evidence.")
    return {"since": since, "since_utc": UTC(since) if since else None, "runs": out, "infra_states": states, "note": note}


def _fraud_runs(store, limit=20) -> list[dict]:
    return fraud_history(store, limit=limit)["runs"]


def _num(v, unit=""):
    return "not measured" if v is None else f"{v}{unit}"


def _cov_text(c: dict) -> str:
    return f"{c['ai_endpoints_behind_bigip']} of {c['ai_endpoints']}"


def executive_html(store, aid: str, before: str | None) -> str:
    e = html.escape
    a = store.db.execute("SELECT * FROM assessment WHERE id=?", (aid,)).fetchone()
    cmp_ = compare(store, before, aid) if before else None
    fs = _findings(store, aid)
    sec = security_results(store, aid)
    vp = cmp_["validation_performance"] if cmp_ else None
    fh = cmp_["fraud_runs"] if cmp_ else fraud_history(store, limit=8)
    ok_deps = [d for d in (cmp_ or {}).get("deployments", []) if d.get("in_place")]
    past_deps = [d for d in (cmp_ or {}).get("deployments", []) if d["status"] == "succeeded" and not d.get("in_place")]
    css = ("body{font-family:system-ui;margin:2.2rem auto;max-width:980px;color:#1b1f24;line-height:1.5}h1{margin-bottom:0}"
           ".sub{color:#57606a}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}.tile{border:1px solid #d0d7de;"
           "border-radius:10px;padding:12px}.tile b{font-size:26px;display:block}table{border-collapse:collapse;width:100%}td,th{border-bottom:"
           "1px solid #d0d7de;padding:6px;font-size:13px;text-align:left}.note{color:#57606a;font-size:12px}@media print{button{display:none}}")
    parts = [f"<!doctype html><html><head><meta charset=utf-8><title>Executive summary — {e(a['name'])}</title><style>{css}</style></head><body>",
             "<button onclick='window.print()'>Print / save as PDF</button>",
             f"<h1>Agentic AI delivery &amp; security — executive summary</h1><p class=sub>{e(a['name'])} · generated "
             f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} by F5 Agentic AI Autopilot · synthetic lab data only</p>"]
    if cmp_:
        cp = cmp_["comparability"]
        parts.append(_comparability_banner(cmp_))
        s, cb, ca = cmp_["summary"], cmp_["coverage"]["before"], cmp_["coverage"]["after"]
        parts.append(f"<p class=note>Before: <b>{e((cp.get('before') or {}).get('name') or before)}</b> (created {UTC((cp.get('before') or {}).get('created'))}) · "
                     f"After: <b>{e(a['name'])}</b> (discovered {UTC(cp.get('after_discovered_at'))}) · counts are findings (one rule on one "
                     f"affected service); the baseline had {s['findings_before']} findings across {s['risk_types_before']} risk types.</p>")
        parts.append(f"<div class=grid><div class=tile><b>{s['resolved']}</b>risks resolved — verified by tests</div>"
                     f"<div class=tile><b>{s['awaiting_rediscovery']}</b>enforcement validated — awaiting rediscovery</div>"
                     f"<div class=tile><b>{s['remaining']}</b>remaining ({s['not_addressed']} not addressed by any package)</div>"
                     f"<div class=tile><b>{_cov_text(cb)} → {_cov_text(ca)}</b>A2A/MCP endpoints fronted by BIG-IP ({cb['percent']}% → {ca['percent']}%)</div>"
                     f"<div class=tile><b>{len(ok_deps)}</b>approved F5 changes in place now</div></div>"
                     f"<p class=note>AI services fronted by BIG-IP (Overview definition): {ca['services']['fronted']} of {ca['services']['total']}. "
                     f"{e(COVERAGE_DEFINITIONS['endpoints'])} {e(COVERAGE_DEFINITIONS['scope'])}</p>")
    by_class: dict = {}
    for f in (cmp_["findings"] if cmp_ else fs):
        by_class.setdefault(f.get("class_label") or "Other", []).append(f)
    parts.append(("<h2>What we found (baseline assessment)</h2>" if cmp_ else "<h2>What we found</h2>") + "<ul>" + "".join(
        f"<li><b>{e(k)}</b>: {len(v)} — " + e("; ".join(sorted({f.get('issue') or f['title'] for f in v}))[:400]) + "</li>" for k, v in by_class.items()) + "</ul>")
    if cmp_:
        parts.append("<h2>What F5 changed (human-approved)</h2>" + ("<ul>" + "".join(
            f"<li>{e(d.get('title') or d['package_id'])} — deployment <code>{e(d['id'])}</code> {UTC(d['started'])} by {e(d['requested_by'])}, "
            f"validation gate {e((d['gate'] or {}).get('status') or 'n/a')} — <b>in place</b></li>" for d in ok_deps) + "</ul>" if ok_deps else
            "<p>No deployment is in place — no remediation is claimed.</p>")
            + ("<p class=note>Historical (succeeded, since removed — not current protection): " + e(", ".join(
                f"{d.get('title') or d['package_id']} {d['id']} {UTC(d['started'])}" for d in past_deps)) + "</p>" if past_deps else ""))
        res = [f for f in cmp_["findings"] if f["outcome"].startswith("resolved")]
        wait = [f for f in cmp_["findings"] if f["outcome"].startswith("awaiting rediscovery")]
        parts.append("<h2>Verified outcomes</h2>" + ("<ul>" + "".join(f"<li>{e(f['rule_id'])} {e(f.get('issue') or f['title'])}: <b>{e(f['outcome'])}</b></li>"
                                                                   for f in res) + "</ul>" if res else "<p>None yet.</p>"))
        if wait:
            parts.append("<h2>Enforcement validated, awaiting rediscovery</h2><p class=note>The 'after' discovery ran before the protection now in "
                         "place; these findings were still observed then. Their proving tests pass against the deployment in place — run a new "
                         "discovery to confirm they are gone. They are not counted as resolved.</p><ul>" + "".join(
                             f"<li>{e(f['rule_id'])} {e(f['title'])} — " + e(", ".join(f"{t['test']} {t['result']} {UTC(t.get('at'))}"
                                                                                for t in f['evidence']['tests'])) + "</li>" for f in wait) + "</ul>")
    if sec:
        when = f" (run {UTC(sec[0]['at'])}, {e(sec[0]['source'])})"
        ran = [t for t in sec if t["result"] != "not_run"]
        parts.append(f"<h2>Security enforcement (tested live)</h2><p>{sum(t['result'] == 'pass' for t in ran)}/{len(ran)} enforcement tests passed{when}: "
                     + e(", ".join(t["test"].replace("security.", "") for t in ran if t["result"] == "pass")) + "</p>")
    if vp:
        parts.append("<h2>Performance (equivalent validator workload)</h2><table><tr><th>state</th><th>measured</th><th>MCP p50</th><th>MCP p95</th>"
                     "<th>A2A investigation</th></tr>" + "".join(
                         f"<tr><td>{e(p['profile'])}</td><td>{UTC(p['measured_at']) if p['measured_at'] else 'no run'}</td><td>{_num(p['mcp_p50_ms'], ' ms')}</td>"
                         f"<td>{_num(p['mcp_p95_ms'], ' ms')}</td><td>{_num(p['a2a_task_s'], ' s')}</td></tr>" for p in vp["rows"])
                     + f"</table><p class=note>{e(vp['statement'])}</p>")
    if fh["runs"]:
        parts.append(f"<h2>Fraud application runs{' since ' + fh['since_utc'] if fh.get('since_utc') else ''}</h2><table><tr><th>time</th><th>scenario</th>"
                     "<th>infrastructure at run time</th><th>decision</th><th>seconds</th><th>paths</th></tr>" +
                     "".join(f"<tr><td>{e(r['created_utc'])}</td><td>{e(r['scenario'])}</td><td>{e(r['infra_state'])}</td><td>{e(r['decision'] or r['state'])}</td>"
                             f"<td>{r['seconds']}</td><td>{e(json.dumps(r['paths'] or {}))}</td></tr>" for r in fh["runs"][:12]) + "</table>"
                     + (f"<p class=note>{e(fh['note'])}</p>" if fh.get("note") else ""))
    elif cmp_:
        parts.append("<h2>Fraud application runs</h2><p class=note>No fraud scenario ran in this comparison window.</p>")
    rem = [f for f in (cmp_["findings"] if cmp_ else []) if f["outcome"].startswith("remaining")]
    gaps = sorted({(f["rule_id"], f.get("not_addressed")) for f in (rem if cmp_ else fs) if f.get("not_addressed")})
    other = sorted({(f["rule_id"], f["outcome"]) for f in rem if not f.get("not_addressed")})
    if gaps or other:
        parts.append("<h2>Remaining gaps &amp; next steps</h2><ul>" + "".join(f"<li><b>{e(r)}</b> — {e(t)}</li>" for r, t in gaps)
                     + "".join(f"<li><b>{e(r)}</b> — still observed: {e(o)}</li>" for r, o in other) + "</ul>")
    parts.append("<p class=note>Every statement is derived from collected evidence; resolved items require a successful, linked deployment that is "
                 "in place, rediscovery that no longer observes the finding, AND passing validation tests of that deployment. The technical "
                 "evidence report contains the underlying data, digests, journals and the same comparison model.</p></body></html>")
    return "".join(parts)


def annotate_runs(vals: list[dict]) -> list[dict]:
    """Each run with effective counts (window-locked checks are 'not run'), the run that supersedes it (newer run of the same
    profile) and the validator-client-defect note. Runs are kept — nothing is hidden — but only current, valid runs are evidence."""
    out = sorted(vals, key=lambda v: v["started"] or 0)
    for i, v in enumerate(out):
        eff = [validation_evidence.effective(t) for t in v["results"]]
        v["effective"] = {"pass": eff.count("pass"), "fail": eff.count("fail"), "not_run": eff.count("not_run"), "ran": eff.count("pass") + eff.count("fail")}
        v["note"] = validation_evidence.run_note(v["results"])
        later = [w for w in out[i + 1:] if w["label"] == v["label"]]
        v["superseded_by"] = later[-1]["id"] if later else None
    return out


def evidence_bundle(store, aid: str, before: str | None) -> dict:
    a = dict(store.db.execute("SELECT * FROM assessment WHERE id=?", (aid,)).fetchone())
    ev = [dict(r) for r in store.db.execute("SELECT id, source, method, collected_at, summary, digest FROM evidence WHERE assessment_id IN (?,?) "
                                            "ORDER BY collected_at", (aid, before or aid))]
    pk = [dict(r) for r in store.db.execute("SELECT id, assessment_id, kind, title, target, created FROM package WHERE assessment_id IN (?,?)", (aid, before or aid))]
    for p in pk:
        p["approvals"] = [dict(x) for x in store.db.execute("SELECT id, decision, approver, role, package_hash, device_fingerprint, created, expires, "
                                                            "consumed_by, comment FROM approval WHERE package_id=? ORDER BY created", (p["id"],))]
        p["reviews"] = [dict(x) | {"checks": json.loads(x["checks"])} for x in store.db.execute(
            "SELECT * FROM package_review WHERE package_id=? ORDER BY created", (p["id"],))]
    deps = [dict(r) | {"steps": json.loads(r["steps"])} for r in store.db.execute(
        "SELECT * FROM deployment WHERE package_id IN (SELECT id FROM package WHERE assessment_id IN (?,?)) ORDER BY started", (aid, before or aid))]
    for d in deps:
        d.pop("previous_state", None)
    vals = annotate_runs([dict(r) | {"results": json.loads(r["results"])} for r in store.db.execute(
        "SELECT * FROM validation_run WHERE assessment_id IN (?,?) ORDER BY started", (aid, before or aid))])
    audit = [dict(r) for r in store.db.execute("SELECT seq, ts, actor, action, assessment_id, detail FROM audit WHERE action LIKE 'package.%' OR "
                                               "action LIKE 'approval.%' OR action LIKE 'deployment.%' OR action LIKE 'live_window.%' OR "
                                               "action LIKE 'reset_demo.%' OR action LIKE 'validation.%' ORDER BY seq")]
    cmp_ = compare(store, before, aid) if before else None
    return {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "generator": "F5 Agentic AI Autopilot", "synthetic_data_only": True,
            "assessment": a, "before_assessment": before, "comparison": cmp_,
            "findings": _findings(store, aid), "evidence_index": ev, "packages": pk, "deployments": deps, "validation_runs": vals,
            # the same comparison-scoped evidence the executive summary shows (doc 38: one model for every export)
            "performance": cmp_["validation_performance"] if cmp_ else {"rows": perf_comparison(store), "comparable": False,
                                                                          "statement": "no comparison selected — absolute measurements only"},
            "fraud_runs": cmp_["fraud_runs"] if cmp_ else fraud_history(store), "security_enforcement": security_results(store, aid),
            "audit": audit,
            "integrity_note": "evidence_index digests are SHA-256 over the stored raw evidence; the audit log is append-only (DB triggers)."}
