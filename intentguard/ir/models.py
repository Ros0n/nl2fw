from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Direction(str, Enum):
    ingress = "ingress"  # maps to INPUT
    egress = "egress"  # maps to OUTPUT
    transit = "transit"  # maps to FORWARD


class Action(str, Enum):
    allow = "allow"
    deny = "deny"
    reject = "reject"


class Protocol(str, Enum):
    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"


class ConnState(str, Enum):
    new = "new"
    established = "established"
    related = "related"


class Match(BaseModel):
    source_cidrs: List[str] = Field(default_factory=list)
    destination_cidrs: List[str] = Field(default_factory=list)
    protocol: Optional[Protocol] = None
    ports: List[int] = Field(default_factory=list)
    connection_state: List[ConnState] = Field(default_factory=list)


class IRRule(BaseModel):
    rule_id: str
    direction: Direction
    match: Match
    action: Action
    logging: bool = False


class IRPolicy(BaseModel):
    default_policy: Action = Action.deny  # used as default chain policy (DROP)
    rules: List[IRRule] = Field(default_factory=list)

