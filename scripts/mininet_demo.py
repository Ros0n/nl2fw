from __future__ import annotations

import json

from intentguard.context.models import load_context
from intentguard.pipeline.compile import compile_intentguard
from intentguard.sim.mininet.helpers import (
    apply_iptables_commands,
    apply_firewall_baseline,
    basic_connectivity_tests,
    flush_conntrack,
    show_rules,
)
from intentguard.sim.mininet.topology import build_intentguard_topology


def main() -> None:
    # Minimal demo harness (run with sudo)
    ctx = load_context("contexts/example/context.yaml")
    nl = "Allow admin_host to access web_server on https"
    result = compile_intentguard(nl_policy=nl, ctx=ctx)

    handles = build_intentguard_topology()
    net = handles.net
    net.start()
    try:
        flush_conntrack(handles.firewall)
        apply_firewall_baseline(handles.firewall)
        apply_iptables_commands(handles.firewall, result.iptables.commands)
        print(show_rules(handles.firewall))

        print(
            json.dumps(
                {
                    "admin_to_web": basic_connectivity_tests(src=handles.h_admin, dst=handles.h_web),
                    "guest_to_web": basic_connectivity_tests(src=handles.h_guest, dst=handles.h_web),
                },
                indent=2,
            )
        )
    finally:
        net.stop()


if __name__ == "__main__":
    main()

