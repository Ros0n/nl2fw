from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Literal, Sequence

from ..ir.models import Action, ConnState, Direction, IRPolicy, IRRule


Chain = Literal["INPUT", "OUTPUT", "FORWARD"]


def _chain_for_direction(d: Direction) -> Chain:
    if d == Direction.ingress:
        return "INPUT"
    if d == Direction.egress:
        return "OUTPUT"
    return "FORWARD"


def _iptables_action(a: Action) -> str:
    return {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}[a.value]


def _sorted_cidrs(cidrs: Sequence[str]) -> List[str]:
    return sorted(
        set(cidrs), key=lambda x: (ipaddress.ip_network(x, strict=False).version, x)
    )


def _states_to_flag(states: Sequence[ConnState]) -> str | None:
    if not states:
        return None
    mapping = {
        ConnState.new: "NEW",
        ConnState.established: "ESTABLISHED",
        ConnState.related: "RELATED",
    }
    parts = [mapping[s] for s in states]
    # deterministic order
    parts = [p for p in ["NEW", "ESTABLISHED", "RELATED"] if p in set(parts)]
    return ",".join(parts)


@dataclass(frozen=True)
class IptablesProgram:
    """Deterministic iptables filter-table program.

    Output is a list of commands (no raw blob).
    """

    commands: List[List[str]]

    def as_shell_lines(self) -> List[str]:
        return [" ".join(cmd) for cmd in self.commands]


def generate_iptables(
    policy: IRPolicy,
    *,
    include_baseline: bool = False,
    include_established_related: bool = False,
) -> IptablesProgram:
    cmds: List[List[str]] = []

    # IMPORTANT SCOPE RULE:
    # IntentGuard compiles *rules for the user intent*, not whole-firewall configuration.
    # Baseline operations (flush/default policies/conntrack baseline) are opt-in for demos.
    if include_baseline:
        cmds.extend(
            [
                ["iptables", "-t", "filter", "-F"],
                ["iptables", "-t", "filter", "-X"],
            ]
        )
        default = "DROP" if policy.default_policy == Action.deny else "ACCEPT"
        for ch in ["INPUT", "OUTPUT", "FORWARD"]:
            cmds.append(["iptables", "-t", "filter", "-P", ch, default])

    if include_established_related:
        # Optional convenience rule (often installed by operators as baseline)
        for ch in ["INPUT", "OUTPUT", "FORWARD"]:
            cmds.append(
                [
                    "iptables",
                    "-t",
                    "filter",
                    "-A",
                    ch,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                ]
            )

    # Deterministic rule ordering: chain order then rule_id
    chain_buckets: Dict[Chain, List[IRRule]] = {"INPUT": [], "OUTPUT": [], "FORWARD": []}
    for r in policy.rules:
        chain_buckets[_chain_for_direction(r.direction)].append(r)

    for ch in ["INPUT", "OUTPUT", "FORWARD"]:
        for r in sorted(chain_buckets[ch], key=lambda x: x.rule_id):
            target = _iptables_action(r.action)
            states = _states_to_flag(r.match.connection_state)

            srcs = _sorted_cidrs(r.match.source_cidrs)
            dsts = _sorted_cidrs(r.match.destination_cidrs)

            # Expand into deterministic Cartesian product to avoid iptables-set dependencies
            for s in srcs:
                for d in dsts:
                    base: List[str] = ["iptables", "-t", "filter", "-A", ch, "-s", s, "-d", d]

                    if r.match.protocol is not None:
                        base += ["-p", r.match.protocol.value]

                    if r.match.ports:
                        # Only single-port match per rule instance for determinism
                        for p in sorted(set(r.match.ports)):
                            cmd = base.copy()
                            if r.match.protocol is not None and r.match.protocol.value in ("tcp", "udp"):
                                cmd += ["--dport", str(p)]
                            if states:
                                cmd += ["-m", "conntrack", "--ctstate", states]
                            if r.logging:
                                cmds.append(cmd + ["-j", "LOG", "--log-prefix", f"IntentGuard {r.rule_id} "])
                            cmds.append(cmd + ["-j", target])
                    else:
                        cmd = base.copy()
                        if states:
                            cmd += ["-m", "conntrack", "--ctstate", states]
                        if r.logging:
                            cmds.append(cmd + ["-j", "LOG", "--log-prefix", f"IntentGuard {r.rule_id} "])
                        cmds.append(cmd + ["-j", target])

    return IptablesProgram(commands=cmds)