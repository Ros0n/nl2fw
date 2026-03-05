from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Literal

import yaml
from pydantic import BaseModel, Field


class Zone(BaseModel):
    name: str
    cidrs: List[str] = Field(default_factory=list)


class AddressObject(BaseModel):
    name: str
    cidrs: List[str] = Field(default_factory=list)


class Service(BaseModel):
    name: str
    protocol: Literal["tcp", "udp", "icmp"]
    ports: List[int] = Field(default_factory=list)  # empty for icmp


class FirewallIdentity(BaseModel):
    name: str = "firewall"
    cidrs: List[str] = Field(default_factory=list, description="Firewall-owned addresses/CIDRs.")
    default_policy: Literal["DROP", "ACCEPT"] = "DROP"


class ContextBundle(BaseModel):
    zones: List[Zone] = Field(default_factory=list)
    objects: List[AddressObject] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)
    firewall: FirewallIdentity = Field(default_factory=FirewallIdentity)


@dataclass(frozen=True)
class ContextIndex:
    zones: Dict[str, Zone]
    objects: Dict[str, AddressObject]
    services: Dict[str, Service]
    firewall: FirewallIdentity

    def to_llm_index(self) -> Dict[str, object]:
        """Structured context view passed to the LLM for extraction.

        The LLM may *read* CIDRs/ports here but must NOT emit them
        directly; extraction validation enforces that constraint.
        """
        return {
            "firewall": self.firewall.model_dump(),
            "zones": [z.model_dump() for z in self.zones.values()],
            "objects": [o.model_dump() for o in self.objects.values()],
            "services": [s.model_dump() for s in self.services.values()],
        }


def _load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_context(path: str) -> ContextIndex:
    """Load a single YAML context file that describes the whole network.

    This mirrors the original repo idea of a single network description
    file that users upload. It is used both in development (example file)
    and at runtime when users provide their own context.
    """
    raw = _load_yaml(path)
    bundle = ContextBundle.model_validate(raw)

    zones = {z.name: z for z in bundle.zones}
    objects = {o.name: o for o in bundle.objects}
    services = {s.name: s for s in bundle.services}

    return ContextIndex(zones=zones, objects=objects, services=services, firewall=bundle.firewall)


