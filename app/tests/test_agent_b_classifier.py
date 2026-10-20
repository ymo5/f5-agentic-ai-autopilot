from autopilot.fraud import scenarios
from services.agent_b.classifier import calibrate_assessment, classify


def _ev(sc, scores=None, rag=None):
    return classify({"transactions": sc["transactions"]}, sc["account"], [], scores or [], rag or [])


def test_all_eight_suspicious_scenarios_are_evaluated_without_ground_truth_in_classifier():
    suspicious = [s for s in scenarios() if s["kind"] == "suspicious"]
    results = [_ev(s) for s in suspicious]
    assert len(results) == 8
    assert all(r["status"] in {"classified", "abstain"} for r in results)
    # The feature layer must recover the strongest observable patterns, while
    # remaining honest about scenarios whose evidence fields are absent.
    assert sum(r["status"] == "classified" for r in results) >= 4
    assert all(r["dominant_pattern"] is None or r["dominant_pattern"]["score"] >= .62 for r in results)


def test_all_normal_scenarios_abstain_and_cannot_escalate():
    normal = [s for s in scenarios() if s["kind"] == "normal"]
    for sc in normal:
        c = _ev(sc)
        a = calibrate_assessment({"decision": "escalate", "risk_level": "high", "confidence": .9,
                                  "matched_patterns": ["FP-008"]}, c)
        assert c["status"] == "abstain"
        assert a["decision"] in {"close", "monitor"}
        assert a["decision"] != "escalate"
        assert a["uncertainty_reason"]


def test_abstention_policy_keeps_action_and_explanation_consistent():
    classification = {"status": "abstain", "normality_score": .75,
                      "reason": "insufficient evidence", "dominant_pattern": None,
                      "confidence": .4}
    a = calibrate_assessment({"decision": "close", "risk_level": "low", "confidence": .4,
                              "rationale": "monitor for additional activity",
                              "recommended_actions": ["Monitor the account"]}, classification)
    assert a["decision"] == "close"
    assert "No immediate fraud action" in a["rationale"]
    assert "routine monitoring" in a["rationale"]
    assert a["recommended_actions"] == ["No immediate fraud action", "Continue routine monitoring for additional activity"]

    classification["normality_score"] = .30
    a = calibrate_assessment({"decision": "close", "risk_level": "low", "confidence": .4,
                              "rationale": "no issue", "recommended_actions": []}, classification)
    assert a["decision"] == "monitor"
    assert "Monitor for additional activity" in a["rationale"]
    assert "before escalating" in a["rationale"]

    classification = {"status": "classified", "normality_score": .20,
                      "reason": "dominant evidence", "dominant_pattern": {"pattern_id": "FP-001"},
                      "confidence": .92}
    a = calibrate_assessment({"decision": "escalate", "risk_level": "high", "confidence": .95,
                              "matched_patterns": ["FP-001", "FP-002"],
                              "rationale": "escalate for investigation", "recommended_actions": ["Escalate"]}, classification)
    assert a["decision"] == "monitor"
    assert "monitor" in a["rationale"].lower()
    assert "before escalation" in a["rationale"].lower()
    assert all("escalat" not in action.lower() or "before" in action.lower() for action in a["recommended_actions"])


def test_custom_strong_structuring_and_ambiguous_case():
    account = scenarios()[0]["account"]
    strong = {"transactions": [
        {"transaction_id": "TXN-C01", "amount": 9500, "mcc": "4829", "country": "US", "channel": "wire", "timestamp": "2026-10-01T10:00:00+00:00"},
        {"transaction_id": "TXN-C02", "amount": 9700, "mcc": "4829", "country": "US", "channel": "wire", "timestamp": "2026-10-02T10:00:00+00:00"},
    ]}
    ambiguous = {"transactions": [
        {"transaction_id": "TXN-C03", "amount": 1200, "mcc": "5999", "country": "US", "channel": "wire"},
        {"transaction_id": "TXN-C04", "amount": 1300, "mcc": "5732", "country": "CA", "channel": "p2p"},
    ]}
    assert classify(strong, account)["dominant_pattern"]["pattern_id"] == "FP-009"
    assert classify(ambiguous, account)["status"] == "abstain"


def test_classifier_does_not_use_scenario_id_or_expected_label():
    sc = scenarios()[0]
    base = {"transactions": sc["transactions"], "scenario_id": "ALERT-9000", "expected_pattern": "FP-010"}
    result = classify(base, sc["account"])
    assert result["dominant_pattern"]["pattern_id"] == "FP-001"
    assert "expected_pattern" not in str(result)


def test_unseen_refund_like_case_abstains_without_refund_evidence():
    account = scenarios()[1]["account"]
    unseen = {"transactions": [
        {"transaction_id": "TXN-U01", "amount": 82, "mcc": "5999", "country": "US", "channel": "card_present"},
        {"transaction_id": "TXN-U02", "amount": 82, "mcc": "5999", "country": "US", "channel": "card_present"},
    ]}
    result = classify(unseen, account)
    assert result["status"] == "abstain"
    assert result["dominant_pattern"] is None
