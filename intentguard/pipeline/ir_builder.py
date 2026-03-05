from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Tuple

from ..context.models import ContextIndex
from ..ir.models import Action, ConnState, Direction, IRPolicy, IRRule, Match, Protocol
from ..llm.extraction_models import ExtractedIntent


class ResolutionError(ValueError):
    pass


def _normalize_name(name: str) -> str:
    return name.strip()


def _expand_entity_to_cidrs(entity: str, ctx: ContextIndex) -> Tuple[str, List[str]]:
    """Resolve a reference name to CIDRs using zones/objects/firewall identity.

    Returns (kind, cidrs) where kind in {"zone","object","firewall"}.
    """
    key = _normalize_name(entity)

    if key == ctx.firewall.name:
        return "firewall", ctx.firewall.cidrs
    if key in ctx.zones:
        return "zone", ctx.zones[key].cidrs
    if key in ctx.objects:
        return "object", ctx.objects[key].cidrs
    raise ResolutionError(f"Unknown reference: {entity}")


def _all_cidrs(refs: Iterable[str], ctx: ContextIndex) -> Tuple[List[str], bool, bool]:
    cidrs: List[str] = []
    saw_firewall = False
    for r in refs:
        kind, rs = _expand_entity_to_cidrs(r, ctx)
        if kind == "firewall":
            saw_firewall = True
        cidrs.extend(rs)
    # de-dupe deterministically
    cidrs = sorted(set(cidrs), key=lambda x: (ipaddress.ip_network(x, strict=False).version, x))
    return cidrs, saw_firewall, bool(cidrs)


def _compute_direction(*, src_has_fw: bool, dst_has_fw: bool) -> Direction:
    # Strict rule: LLM never decides direction. Compiler resolves.
    if dst_has_fw and not src_has_fw:
        return Direction.ingress
    if src_has_fw and not dst_has_fw:
        return Direction.egress
    return Direction.transit


def build_ir_policy(*, extracted: ExtractedIntent, ctx: ContextIndex) -> IRPolicy:
    """Deterministically build canonical IR from extracted intent + context."""

    action = (extracted.action or "").lower().strip()
    if action not in {"allow", "deny", "reject"}:
        raise ResolutionError("Action missing or unsupported (must be allow/deny/reject).")

    if not extracted.sources or not extracted.destinations or not extracted.services:
        raise ResolutionError("Empty rule (sources, destinations, and services are required).")

    src_cidrs, src_has_fw, src_any = _all_cidrs(extracted.sources, ctx)
    dst_cidrs, dst_has_fw, dst_any = _all_cidrs(extracted.destinations, ctx)
    if not src_any or not dst_any:
        raise ResolutionError("Resolved empty CIDR set for source or destination.")

    rules: List[IRRule] = []
    # Deterministic: one rule per service (explicitly constrained project scope)
    for i, svc_name in enumerate(sorted(set(map(_normalize_name, extracted.services)))):
        if svc_name not in ctx.services:
            raise ResolutionError(f"Unknown service: {svc_name}")
        svc = ctx.services[svc_name]

        proto: Optional[Protocol] = Protocol(svc.protocol)
        ports = list(svc.ports)

        direction = _compute_direction(src_has_fw=src_has_fw, dst_has_fw=dst_has_fw)

        match = Match(
            source_cidrs=src_cidrs,
            destination_cidrs=dst_cidrs,
            protocol=proto,
            ports=ports,
            connection_state=[ConnState.new],
        )

        rules.append(
            IRRule(
                rule_id=f"R{i+1}",
                direction=direction,
                match=match,
                action=Action(action),
                logging=bool(extracted.logging) if extracted.logging is not None else False,
            )
        )

    return IRPolicy(default_policy=Action.deny, rules=rules)

