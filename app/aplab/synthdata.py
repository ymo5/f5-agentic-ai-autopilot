"""Deterministic SYNTHETIC financial dataset (no real people, accounts or institutions).

Generates accounts, merchants, transactions (with injected fraud scenarios), a fraud-pattern
knowledge base (RAG corpus for Qdrant) and investigation case documents (stored in S3).
Run: python -m aplab.synthdata <out.json>
"""
from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone

SEED = 20261013
COUNTRIES = ["US", "US", "US", "CA", "GB", "DE", "MX", "BR", "NG", "RO", "SG"]
CHANNELS = ["card_present", "ecommerce", "ach", "wire", "p2p"]
MCC = {"5411": "grocery", "5812": "restaurants", "5999": "misc_retail", "6011": "atm_cash",
       "4829": "money_transfer", "7995": "gambling", "5732": "electronics", "4511": "airlines",
       "6051": "crypto_exchange", "5944": "jewelry"}
HIGH_RISK_MCC = {"4829", "7995", "6051", "5944"}

FRAUD_PATTERNS = [
    ("FP-001", "Card testing", "Many small-value card-not-present authorizations (under $5) across different merchants within minutes, often followed by one large purchase. Indicates stolen card numbers being validated."),
    ("FP-002", "Account takeover", "Login from a new device and country, password or email change, then rapid high-value transfers to newly added payees. Velocity and geography break from the customer's baseline."),
    ("FP-003", "Mule account funnelling", "Account receives many inbound P2P or ACH credits from unrelated senders and forwards most of the balance by wire or crypto exchange within 24 hours."),
    ("FP-004", "Synthetic identity bust-out", "Recently opened account builds a short positive history with small payments, then maxes out credit across electronics and jewelry merchants before going dormant."),
    ("FP-005", "Authorized push payment scam", "Customer initiates an unusually large first-time wire to a new beneficiary, often abroad, sometimes after a call from someone impersonating the bank or a vendor."),
    ("FP-006", "Merchant collusion / refund abuse", "Repeated refunds or chargebacks concentrated at a single merchant with transactions just under review thresholds."),
    ("FP-007", "Crypto cash-out", "Rapid conversion of incoming funds via crypto exchange merchants (MCC 6051) shortly after large deposits, especially for accounts with no prior crypto activity."),
    ("FP-008", "Gambling-linked laundering", "Round-amount deposits to gambling merchants with quick withdrawals and minimal play, layered across several accounts."),
    ("FP-009", "Structuring", "Multiple cash or transfer transactions just below the $10,000 reporting threshold over consecutive days."),
    ("FP-010", "Geographic impossibility", "Card-present transactions in two distant countries within a time window too short for travel."),
]


def build() -> dict:
    rng = random.Random(SEED)
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    first = ["Avery", "Jordan", "Riley", "Casey", "Morgan", "Quinn", "Reese", "Skyler", "Dakota", "Emerson"]
    last = ["Nguyen", "Okafor", "Larsen", "Moreau", "Schmidt", "Silva", "Kowalski", "Tanaka", "Haddad", "Reyes"]
    accounts = []
    for i in range(1, 121):
        accounts.append({
            "account_id": f"ACC-{100000 + i}",
            "holder": f"{rng.choice(first)} {rng.choice(last)} (synthetic)",
            "opened": (now - timedelta(days=rng.randint(20, 3000))).date().isoformat(),
            "home_country": rng.choice(["US", "US", "US", "CA", "GB"]),
            "segment": rng.choice(["retail", "retail", "premier", "small_business"]),
            "avg_monthly_spend": round(rng.uniform(400, 9000), 2),
            "kyc_risk": rng.choice(["low", "low", "low", "medium", "high"]),
        })
    pattern_order = ["FP-001", "FP-002", "FP-003", "FP-005", "FP-007", "FP-009", "FP-010", "FP-004"]
    pattern_accounts = {p: accounts[k * 7 + 3] for k, p in enumerate(pattern_order)}
    # Scenario-specific account context is observable evidence, not a label.  It
    # mirrors the fields a production fraud service would receive from identity,
    # device, beneficiary and account-history systems.
    takeover = pattern_accounts["FP-002"]
    takeover.update({"home_country": "US", "known_device_ids": ["DEV-BASE-02"],
                     "credential_change_at": (now - timedelta(minutes=35)).isoformat(),
                     "new_payee_id": "PAYEE-NEW-02"})
    synthetic = pattern_accounts["FP-004"]
    synthetic.update({"opened": (now - timedelta(days=45)).date().isoformat(),
                      "avg_monthly_spend": 320.0, "kyc_risk": "low", "known_device_ids": ["DEV-BASE-04"]})
    merchants = [{"merchant_id": f"MER-{2000 + i}", "name": f"Synthetic Merchant {i}",
                  "mcc": (m := rng.choice(list(MCC))), "category": MCC[m],
                  "country": rng.choice(COUNTRIES)} for i in range(1, 61)]
    txns = []
    tid = 500000
    for a in accounts:
        for _ in range(rng.randint(8, 20)):
            m = rng.choice(merchants)
            tid += 1
            txns.append({"transaction_id": f"TXN-{tid}", "account_id": a["account_id"],
                         "merchant_id": m["merchant_id"], "mcc": m["mcc"],
                         "amount": round(rng.lognormvariate(3.6, 1.0), 2),
                         "currency": "USD", "country": rng.choice([a["home_country"]] * 6 + [m["country"]]),
                         "channel": rng.choice(CHANNELS),
                         "timestamp": (now - timedelta(minutes=rng.randint(0, 60 * 24 * 30))).isoformat(),
                         "label": "legit"})
    # The synthetic identity account has a short, genuinely positive history;
    # remove the generic random history for that account and replace it with
    # three small purchases before the bust-out.
    synthetic_id = synthetic["account_id"]
    txns = [t for t in txns if t["account_id"] != synthetic_id]
    for j, (days, amount) in enumerate(((30, 24.50), (20, 41.20), (10, 18.75)), 1):
        tid += 1
        txns.append({"transaction_id": f"TXN-{tid}", "account_id": synthetic_id, "merchant_id": merchants[j]["merchant_id"],
                     "mcc": "5411", "amount": amount, "currency": "USD", "country": synthetic["home_country"],
                     "channel": "card_present", "timestamp": (now - timedelta(days=days)).isoformat(), "label": "legit"})

    # Inject realistic, internally consistent fraud scenarios.  The alert IDs
    # and order are stable for existing fixtures; Agent B receives only the
    # resulting evidence, never the pattern variable used here.
    scenarios = []
    for k, pattern in enumerate(pattern_order):
        a = pattern_accounts[pattern]
        base = now - timedelta(hours=rng.randint(1, 72))
        ids = []
        if pattern == "FP-001":
            tx_specs = [(2.14, "5411", "ecommerce", "US"), (3.41, "5812", "ecommerce", "US"),
                        (1.89, "5999", "ecommerce", "US"), (4.21, "5732", "ecommerce", "US"),
                        (1240.00, "5732", "ecommerce", "US")]
        elif pattern == "FP-002":
            tx_specs = [(1850.00, "5999", "ecommerce", "GB"), (6200.00, "4829", "wire", "NG"),
                        (4100.00, "4829", "wire", "NG"), (2750.00, "4829", "p2p", "NG")]
        elif pattern == "FP-003":
            tx_specs = [(1800.00, "5411", "ach", "US"), (2200.00, "5411", "p2p", "US"),
                        (1950.00, "5411", "ach", "US"), (5200.00, "4829", "wire", "NG"),
                        (4100.00, "4829", "wire", "NG"), (3000.00, "6051", "p2p", "NG")]
        elif pattern == "FP-005":
            tx_specs = [(12500.00, "5411", "wire", "GB")]
        elif pattern == "FP-007":
            tx_specs = [(14500.00, "5411", "wire", "US"), (7200.00, "6051", "p2p", "US"),
                        (6100.00, "6051", "p2p", "US")]
        elif pattern == "FP-009":
            tx_specs = [(9340.00, "6011", "wire", "US"), (9725.00, "5411", "wire", "US"),
                        (9860.00, "4829", "ach", "US"), (9180.00, "6011", "wire", "US")]
        elif pattern == "FP-010":
            tx_specs = [(185.00, "5411", "card_present", "US"), (240.00, "5411", "card_present", "SG"),
                        (310.00, "5411", "card_present", "RO"), (275.00, "5411", "card_present", "BR")]
        else:  # FP-004: new account, short positive history, then high-value bust-out.
            tx_specs = [(4800.00, "5732", "ecommerce", "US"), (7350.00, "5944", "ecommerce", "US"),
                        (9200.00, "5732", "ecommerce", "US")]
        for j, (amt, mcc, channel, country) in enumerate(tx_specs):
            m = (merchants[j % len(merchants)] if pattern == "FP-001"
                 else next((x for x in merchants if x["mcc"] == mcc), merchants[0]))
            tid += 1
            step = j * (1440 if pattern == "FP-009" else 20)
            item = {"transaction_id": f"TXN-{tid}", "account_id": a["account_id"], "merchant_id": m["merchant_id"],
                    "mcc": mcc, "amount": amt, "currency": "USD", "country": country, "channel": channel,
                    "timestamp": (base + timedelta(minutes=step)).isoformat(), "label": "fraud"}
            if pattern == "FP-002":
                item.update({"device_id": "DEV-NEW-02", "beneficiary_id": "PAYEE-NEW-02", "credential_event": "password_changed",
                             "direction": "outbound"})
            elif pattern == "FP-003":
                if j < 3:
                    item.update({"direction": "inbound", "sender_id": f"SENDER-{j + 1:02d}"})
                else:
                    item.update({"direction": "outbound", "beneficiary_id": f"PAYEE-MULE-{j - 2:02d}"})
            elif pattern == "FP-007":
                item["direction"] = "inbound" if j == 0 else "outbound"
            txns.append(item)
            ids.append(f"TXN-{tid}")
        scenarios.append({"alert_id": f"ALERT-{9000 + k}", "account_id": a["account_id"],
                          "transaction_ids": ids, "trigger": "rules engine velocity/geo alert"})
    cases = [{"case_id": f"CASE-{7000 + i}", "pattern_id": p[0],
              "title": f"Closed investigation: {p[1]}",
              "body": (f"SYNTHETIC CASE FILE {7000 + i}\nPattern: {p[1]} ({p[0]})\nSummary: {p[2]}\n"
                       f"Outcome: {'confirmed fraud, funds recalled' if i % 2 == 0 else 'confirmed fraud, account closed'}\n"
                       "Analyst notes: indicators matched within 48h; recommend velocity rule tuning.")}
             for i, p in enumerate(FRAUD_PATTERNS)]
    return {"generated": now.isoformat(), "seed": SEED, "synthetic": True,
            "accounts": accounts, "merchants": merchants, "transactions": txns, "alerts": scenarios,
            "fraud_patterns": [{"pattern_id": p[0], "name": p[1], "text": p[2]} for p in FRAUD_PATTERNS],
            "case_documents": cases, "mcc": MCC, "high_risk_mcc": sorted(HIGH_RISK_MCC)}


if __name__ == "__main__":
    data = build()
    with open(sys.argv[1] if len(sys.argv) > 1 else "synthetic.json", "w") as f:
        json.dump(data, f, indent=1)
    print(f"accounts={len(data['accounts'])} txns={len(data['transactions'])} alerts={len(data['alerts'])}")
