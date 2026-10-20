"""Request parsing for Agent B: dataset alerts (ALERT-nnnn) or an inline, operator-composed synthetic scenario.

Inline scenarios are validated strictly (synthetic account id format, 1..6 transactions, bounded amounts, known field
shapes); anything else is rejected. Agent B still gathers all other evidence (account profile, recent transactions, RAG
patterns, case file, model scores) through MCP exactly as for dataset alerts.
"""
from __future__ import annotations

import json
import re

MARKER = "SCENARIO-JSON:"
CHANNELS = {"card_present", "ecommerce", "ach", "wire", "p2p"}
DIRECTIONS = {"inbound", "outbound", "credit", "debit"}


class ScenarioError(ValueError):
    pass


def parse_request(text: str) -> tuple[str, dict | None]:
    """Return (request id, inline alert or None). Raises ScenarioError for invalid requests."""
    if MARKER in text:
        try:
            sc = json.loads(text.split(MARKER, 1)[1].strip())
        except ValueError as e:
            raise ScenarioError("scenario JSON is not valid") from e
        sid = str(sc.get("scenario_id", ""))
        if not re.fullmatch(r"NORMAL-\d|CUSTOM-[a-f0-9]{6}", sid):
            raise ScenarioError("scenario_id must be NORMAL-n or CUSTOM-xxxxxx")
        if not re.fullmatch(r"ACC-\d{6}", str(sc.get("account_id", ""))):
            raise ScenarioError("account_id must be a synthetic ACC-nnnnnn id")
        txs = sc.get("transactions")
        if not isinstance(txs, list) or not 1 <= len(txs) <= 6:
            raise ScenarioError("1..6 transactions required")
        clean = []
        for t in txs:
            try:
                amt = float(t["amount"])
            except (KeyError, TypeError, ValueError) as e:
                raise ScenarioError("transaction amount missing") from e
            if not (0.01 <= amt <= 50000 and re.fullmatch(r"TXN-[A-Z0-9]{1,8}", str(t.get("transaction_id", "")))
                    and re.fullmatch(r"\d{4}", str(t.get("mcc", ""))) and re.fullmatch(r"[A-Z]{2}", str(t.get("country", "")))
                    and t.get("channel") in CHANNELS):
                raise ScenarioError("transaction fields out of bounds")
            ts = t.get("timestamp")
            if ts:
                try:
                    __import__("datetime").datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                except ValueError as e:
                    raise ScenarioError("timestamp must be ISO-8601") from e
            direction = t.get("direction")
            if direction and direction not in DIRECTIONS:
                raise ScenarioError("direction must be inbound, outbound, credit, or debit")
            clean.append({"transaction_id": t["transaction_id"], "amount": round(amt, 2), "mcc": str(t["mcc"]),
                          "category": str(t.get("category") or "")[:30], "country": t["country"], "channel": t["channel"],
                          **{k: t[k] for k in ("timestamp", "direction", "merchant_id", "merchant_name", "beneficiary_id",
                                                "sender_id", "device_id", "temporal_relation_minutes") if t.get(k) is not None}})
        return sid, {"alert_id": sid, "account_id": sc["account_id"], "transactions": clean, "trigger": "operator test scenario"}
    m = re.search(r"ALERT-\d+", text)
    if not m:
        raise ScenarioError("Request must reference an alert id (ALERT-nnnn) or carry a synthetic scenario.")
    return m.group(0), None
