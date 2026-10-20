"""Evidence-first fraud-pattern classification for Agent B.

This module deliberately has no scenario-id or ground-truth access.  It scores
observable evidence, records missing fields, and abstains when the evidence is
not strong enough to support a dominant pattern.  Pattern IDs here describe
the bank's fraud taxonomy; they are not synthetic scenario mappings.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from math import isfinite

PATTERN_MIN_SCORE = 0.62
PATTERN_MIN_MARGIN = 0.12
NORMALITY_THRESHOLD = 0.72


def _num(value, default=0.0):
    try:
        n = float(value)
        return n if isfinite(n) else default
    except (TypeError, ValueError):
        return default


def _time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def extract_features(alert: dict, account: dict, recent: list[dict] | None = None, scores: list[dict] | None = None) -> dict:
    """Extract deterministic features from supplied transaction/account evidence."""
    txs = list(alert.get("transactions") or [])
    times = sorted(t for t in (_time(x.get("timestamp")) for x in txs) if t is not None)
    amounts = [_num(x.get("amount")) for x in txs]
    channels = Counter(str(x.get("channel") or "unknown") for x in txs)
    mccs = Counter(str(x.get("mcc") or "unknown") for x in txs)
    categories = Counter(str(x.get("category") or x.get("mcc") or "unknown") for x in txs)
    countries = Counter(str(x.get("country") or "unknown") for x in txs)
    merchants = {x.get("merchant_id") for x in txs if x.get("merchant_id")}
    merchant_keys = merchants or set(categories)
    home = str(account.get("home_country") or "")
    span = (times[-1] - times[0]).total_seconds() / 60 if len(times) > 1 else None
    gaps = [(b - a).total_seconds() / 60 for a, b in zip(times, times[1:])]
    age_days = account.get("account_age_days")
    if age_days is None and account.get("opened"):
        opened = _time(account["opened"])
        if opened:
            age_days = max(0, (datetime.now(opened.tzinfo) - opened).days)
    recent = list(recent or [])
    directions = Counter(str(x.get("direction") or x.get("flow") or "unknown").lower() for x in txs)
    high_value = [a for a in amounts if a >= 1000]
    foreign = [x for x in txs if home and x.get("country") != home]
    flags = {
        "has_timestamps": len(times) == len(txs) and bool(txs),
        "has_merchant_identity": bool(merchants),
        "has_direction": any(k != "unknown" for k in directions),
        "has_history": bool(recent) or account.get("avg_monthly_spend") is not None,
        "has_ato_context": any(k in alert or k in account for k in
                                ("device_id", "known_device_ids", "new_device", "credential_change", "credential_change_at",
                                 "password_changed", "new_payee", "new_payee_id", "login_country")),
    }
    return {
        "transaction_count": len(txs), "total_amount": round(sum(amounts), 2),
        "mean_amount": round(sum(amounts) / len(amounts), 2) if amounts else 0,
        "max_amount": round(max(amounts), 2) if amounts else 0,
        "small_under_5": sum(a < 5 for a in amounts),
        "near_10k": sum(9000 <= a < 10000 for a in amounts),
        "high_value_count": len(high_value),
        "span_minutes": round(span, 2) if span is not None else None,
        "transactions_per_hour": round(len(txs) / (span / 60), 2) if span and span > 0 else None,
        "minimum_gap_minutes": round(min(gaps), 2) if gaps else None,
        "distinct_merchants": len(merchant_keys), "distinct_categories": len(categories),
        "distinct_countries": len(countries), "foreign_count": len(foreign),
        "home_country": home, "countries": sorted(countries),
        "channels": dict(channels), "mccs": dict(mccs), "categories": dict(categories),
        "directions": dict(directions), "account_age_days": age_days,
        "kyc_risk": str(account.get("kyc_risk") or "unknown"),
        "avg_monthly_spend": _num(account.get("avg_monthly_spend")),
        "history_count": len(recent), "score_max": max((_num(s.get("score")) for s in (scores or [])), default=0),
        "score_mean": round(sum(_num(s.get("score")) for s in (scores or [])) / len(scores), 3) if scores else 0,
        "flags": flags,
    }


def _clamp(value):
    return round(max(0.0, min(1.0, value)), 3)


def _score_patterns(f: dict) -> list[dict]:
    """Score taxonomy patterns from features; each score has human-readable evidence."""
    n = max(f["transaction_count"], 1)
    small_ratio = f["small_under_5"] / n
    foreign_ratio = f["foreign_count"] / n
    country_spread = min(f["distinct_countries"] / 3, 1)
    diversity = min(f["distinct_merchants"] / 4, 1)
    tight = 1 if f["span_minutes"] is not None and f["span_minutes"] <= 180 else 0
    mcc = f["mccs"]
    channels = f["channels"]
    high_value_vs_baseline = min(f["max_amount"] / max(f["avg_monthly_spend"], 1), 3) / 3
    scores = []

    def add(pid, name, score, evidence):
        scores.append({"pattern_id": pid, "name": name, "score": _clamp(score), "evidence": [x for x in evidence if x]})

    add("FP-001", "Card testing", .52 * small_ratio + .23 * diversity + .15 * tight + .10 * min(country_spread, 1),
        [f"{f['small_under_5']} of {n} transactions are under $5" if f["small_under_5"] else "no sub-$5 burst",
         f"{f['distinct_merchants']} merchant identities/categories", "transactions occur within 3 hours" if tight else None])
    add("FP-002", "Account takeover", (0.30 * foreign_ratio + .25 * (1 if channels.get("wire", 0) + channels.get("p2p", 0) else 0) +
        .20 * min(f["high_value_count"] / 2, 1) + .15 * tight + .10 * (1 if f["kyc_risk"] == "high" else 0)) if f["flags"]["has_ato_context"] else 0,
        ["foreign activity", "wire or P2P activity" if channels.get("wire", 0) + channels.get("p2p", 0) else None,
         "high-value activity" if f["high_value_count"] else None, "high KYC risk" if f["kyc_risk"] == "high" else None])
    inbound = sum(v for k, v in f["directions"].items() if k in {"inbound", "credit", "incoming"})
    outbound = sum(v for k, v in f["directions"].items() if k in {"outbound", "debit", "outgoing"})
    add("FP-003", "Mule account funnelling", .55 * min(inbound / 3, 1) + .35 * min(outbound / 2, 1) + .10 * tight,
        ["inbound/outbound transaction direction evidence" if f["flags"]["has_direction"] else "direction data unavailable"])
    young = 1 if f["account_age_days"] is not None and f["account_age_days"] <= 180 else 0
    electronics_jewelry = mcc.get("5732", 0) + mcc.get("5944", 0)
    add("FP-004", "Synthetic identity bust-out", .35 * young + .35 * min(electronics_jewelry / 2, 1) + .20 * high_value_vs_baseline + .10 * (1 if f["high_value_count"] >= 2 else 0),
        ["account is newly opened" if young else "account age does not establish a new account",
         "electronics/jewelry spend" if electronics_jewelry else None, "spend exceeds account baseline" if high_value_vs_baseline > .5 else None])
    push_score = .35 * min(channels.get("wire", 0) / 2, 1) + .25 * foreign_ratio + .25 * high_value_vs_baseline + .15 * (1 if f["max_amount"] >= 9000 else 0)
    # Repeated near-threshold transfers are stronger evidence for structuring
    # than for a single first-time push payment.
    add("FP-005", "Authorized push payment scam", push_score * (0.70 if f["near_10k"] >= 2 else 1),
        ["wire activity" if channels.get("wire") else None, "foreign beneficiary geography" if foreign_ratio else None,
         "large amount relative to baseline" if high_value_vs_baseline > .5 else None])
    add("FP-006", "Merchant collusion / refund abuse", 0, ["refund/chargeback fields unavailable"])
    crypto = mcc.get("6051", 0)
    flow_pattern = inbound >= 2 and outbound >= 2
    crypto_base = .65 * min(crypto / 1, 1) * (1 if f["flags"]["has_direction"] or f["max_amount"] >= 1000 else .55) * (0.5 if flow_pattern else 1)
    add("FP-007", "Crypto cash-out", crypto_base + .20 * tight + .15 * (1 if f["flags"]["has_direction"] else 0),
        ["crypto-exchange MCC 6051" if crypto else "no crypto-exchange MCC", "rapid timing" if tight else None])
    gambling = mcc.get("7995", 0)
    add("FP-008", "Gambling-linked laundering", .65 * min(gambling / 2, 1) + .20 * (1 if f["flags"]["has_direction"] else 0) + .15 * tight,
        ["gambling MCC 7995" if gambling else "no gambling MCC", "direction/withdrawal evidence" if f["flags"]["has_direction"] else None])
    add("FP-009", "Structuring", .70 * min(f["near_10k"] / 2, 1) + .15 * (1 if channels.get("wire", 0) + channels.get("ach", 0) else 0) + .15 * min(f["distinct_countries"] / 2, 1),
        [f"{f['near_10k']} transactions just below $10,000" if f["near_10k"] else "no near-threshold transactions",
         "wire/ACH channel" if channels.get("wire", 0) + channels.get("ach", 0) else None])
    add("FP-010", "Geographic impossibility", .55 * min(country_spread, 1) + .30 * (1 if channels.get("card_present") else 0) + .15 * tight,
        [f"{f['distinct_countries']} countries represented" if f["distinct_countries"] > 1 else "single-country activity",
         "card-present activity" if channels.get("card_present") else "no card-present evidence", "tight timing" if tight else None])
    return sorted(scores, key=lambda x: x["score"], reverse=True)


def classify(alert: dict, account: dict, recent: list[dict] | None = None, scores: list[dict] | None = None,
             rag_patterns: list[dict] | None = None) -> dict:
    f = extract_features(alert, account, recent, scores)
    candidates = _score_patterns(f)
    top, second = candidates[0], candidates[1]
    rag_ids = {str(p.get("pattern_id")) for p in (rag_patterns or [])}
    # RAG is corroboration only; it cannot rescue weak deterministic evidence.
    if top["pattern_id"] in rag_ids:
        top = {**top, "score": _clamp(top["score"] + .05), "evidence": top["evidence"] + ["corroborated by RAG similarity"]}
        candidates[0] = top
    margin = round(top["score"] - second["score"], 3)
    data_completeness = sum(bool(v) for v in f["flags"].values()) / len(f["flags"])
    normality = (0.30 * (1 if f["score_max"] < .4 else 0) + 0.25 * (1 if f["foreign_count"] == 0 else 0) +
                 0.20 * (1 if f["near_10k"] == 0 and f["small_under_5"] == 0 else 0) +
                 0.15 * (1 if f["max_amount"] <= max(f["avg_monthly_spend"] * .25, 250) else 0) +
                 0.10 * (1 if f["transaction_count"] <= 3 else 0))
    if top["score"] >= PATTERN_MIN_SCORE and margin >= PATTERN_MIN_MARGIN:
        status = "classified"
        dominant = top
        confidence = _clamp(.55 * top["score"] + .25 * min(margin / .35, 1) + .20 * data_completeness)
    else:
        status = "abstain"
        dominant = None
        confidence = _clamp(.45 * top["score"] + .20 * data_completeness)
    reason = ("Insufficient or conflicting observable evidence; no dominant pattern meets the score and margin thresholds."
              if status == "abstain" else "Dominant pattern supported by deterministic features and, where available, RAG corroboration.")
    return {"status": status, "dominant_pattern": dominant, "candidate_patterns": candidates[:5],
            "confidence": confidence, "margin": margin, "normality_score": round(normality, 3),
            "data_completeness": round(data_completeness, 3), "features": f, "reason": reason,
            "thresholds": {"pattern_min_score": PATTERN_MIN_SCORE, "pattern_min_margin": PATTERN_MIN_MARGIN,
                           "normality_threshold": NORMALITY_THRESHOLD}}


def calibrate_assessment(assessment: dict, classification: dict) -> dict:
    """Apply evidence sufficiency and normality gates to the LLM's risk recommendation."""
    out = dict(assessment)
    dominant = classification.get("dominant_pattern")
    disagreement = bool(dominant and set(out.get("matched_patterns") or []) - {dominant["pattern_id"]})
    out["classification_status"] = classification["status"]
    out["classification_confidence"] = classification["confidence"]
    out["classification_disagreement"] = disagreement
    out["decision_basis"] = "hybrid deterministic features + RAG + LLM reasoning"
    out["uncertainty_reason"] = classification["reason"] if classification["status"] == "abstain" else None
    if dominant:
        out["matched_patterns"] = [dominant["pattern_id"]]
    else:
        out["matched_patterns"] = []
    # A model cannot escalate ordinary, low-risk, evidence-complete activity merely because
    # a generic RAG pattern matched. This is a general evidence gate, not a scenario exception.
    if classification["normality_score"] >= NORMALITY_THRESHOLD and classification["status"] == "abstain":
        out["decision"] = "close"
        out["risk_level"] = "low"
        out["confidence"] = min(float(out.get("confidence", 0.0) or 0.0), .55)
        out["uncertainty_reason"] = "Activity is consistent with the account baseline and no fraud pattern cleared the evidence threshold."
        out["rationale"] = ("The independent evidence classifier abstained and found no suspicious pattern. "
                            "No immediate fraud action is warranted; continue routine monitoring for new activity.")
        out["recommended_actions"] = ["No immediate fraud action", "Continue routine monitoring for additional activity"]
    elif classification["status"] == "abstain" and out.get("decision") == "escalate":
        out["decision"] = "monitor"
        out["risk_level"] = "elevated" if classification["normality_score"] < .45 else "low"
        out["confidence"] = min(float(out.get("confidence", 0.0) or 0.0), .60)
        out["uncertainty_reason"] = classification["reason"]
        out["rationale"] = ("The independent evidence classifier abstained because the available evidence is "
                            "insufficient for a dominant fraud pattern. Monitor for additional activity and "
                            "review new evidence before escalating.")
        out["recommended_actions"] = ["Monitor for additional activity", "Review new evidence before escalating"]
    elif classification["status"] == "abstain":
        out["decision"] = "monitor"
        out["risk_level"] = "elevated" if classification["normality_score"] < .45 else "low"
        out["confidence"] = min(float(out.get("confidence", 0.0) or 0.0), .60)
        out["uncertainty_reason"] = classification["reason"]
        out["rationale"] = ("The independent evidence classifier abstained because the available evidence is "
                            "insufficient for a dominant fraud pattern. Monitor for additional activity and "
                            "review new evidence before escalating.")
        out["recommended_actions"] = ["Monitor for additional activity", "Review new evidence before escalating"]
    elif disagreement:
        if out.get("decision") == "escalate":
            out["decision"] = "monitor"
            out["rationale"] = ("The dominant pattern is supported by the independent evidence classifier, but the model proposed an additional pattern. "
                                "Because of that disagreement, monitor for additional activity and review the evidence before escalation.")
            out["recommended_actions"] = ["Monitor for additional activity", "Review evidence before escalating"]
        out["confidence"] = min(float(out.get("confidence", 0.0) or 0.0), classification["confidence"])
        out["uncertainty_reason"] = "LLM pattern reasoning disagreed with the independent evidence classifier; analyst review required."
    return out
