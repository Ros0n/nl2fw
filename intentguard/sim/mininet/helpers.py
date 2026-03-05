from __future__ import annotations

from typing import Iterable, List

from mininet.node import Node


def flush_conntrack(node: Node) -> None:
    # conntrack-tools is required; if not installed, command will fail loudly (academic setup).
    node.cmd("conntrack -F || true")


def apply_firewall_baseline(node: Node) -> None:
    """Deterministic baseline for the Mininet demo only (NOT compiler output).

    Keeps IntentGuard scoped to intent->rules, while making simulation repeatable.
    """
    node.cmd("iptables -t filter -F")
    node.cmd("iptables -t filter -X")
    node.cmd("iptables -t filter -P INPUT ACCEPT")
    node.cmd("iptables -t filter -P OUTPUT ACCEPT")
    node.cmd("iptables -t filter -P FORWARD DROP")
    node.cmd("iptables -t filter -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")


def apply_iptables_commands(node: Node, commands: Iterable[List[str]]) -> None:
    for cmd in commands:
        node.cmd(" ".join(cmd))


def show_rules(node: Node) -> str:
    return node.cmd("iptables -t filter -S")


def basic_connectivity_tests(*, src: Node, dst: Node) -> dict:
    """Basic deterministic smoke tests: ping + TCP connect if nc exists."""
    res = {"ping": None, "tcp_80": None}
    res["ping"] = src.cmd(f"ping -c 1 -W 1 {dst.IP()}").strip()
    res["tcp_80"] = src.cmd(f"sh -lc 'command -v nc >/dev/null && nc -z -w 1 {dst.IP()} 80 || echo nc_missing'").strip()
    return res

