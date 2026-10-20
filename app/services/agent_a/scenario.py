"""Validated request model for operator-composed synthetic scenarios (Agent A -> Agent B inline)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Txn(BaseModel):
    transaction_id: str = Field(pattern=r"^TXN-[A-Z0-9]{1,8}$")
    amount: float = Field(ge=0.01, le=50000)
    mcc: str = Field(pattern=r"^\d{4}$")
    category: str = Field(default="", max_length=30)
    country: str = Field(pattern=r"^[A-Z]{2}$")
    channel: Literal["card_present", "ecommerce", "ach", "wire", "p2p"]
    timestamp: str | None = Field(default=None, max_length=40)
    direction: Literal["inbound", "outbound", "credit", "debit"] | None = None
    merchant_id: str | None = Field(default=None, pattern=r"^[A-Z0-9_-]{1,32}$")
    merchant_name: str | None = Field(default=None, max_length=80)
    beneficiary_id: str | None = Field(default=None, pattern=r"^[A-Z0-9_-]{1,32}$")
    sender_id: str | None = Field(default=None, pattern=r"^[A-Z0-9_-]{1,32}$")
    device_id: str | None = Field(default=None, pattern=r"^[A-Z0-9_-]{1,32}$")
    temporal_relation_minutes: float | None = Field(default=None, ge=0, le=10080)


class Scenario(BaseModel):
    scenario_id: str = Field(pattern=r"^(NORMAL-\d|CUSTOM-[a-f0-9]{6})$")
    account_id: str = Field(pattern=r"^ACC-\d{6}$")
    transactions: list[Txn] = Field(min_length=1, max_length=6)


class ScenarioReq(BaseModel):
    scenario: Scenario
