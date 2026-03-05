from __future__ import annotations

from dataclasses import dataclass

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Node


class LinuxRouter(Node):
    """Linux router / firewall node with IP forwarding enabled."""

    def config(self, **params):
        super().config(**params)
        # Enable routing
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        # Disable reverse path filtering (important for multi-interface router)
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        self.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0")
        return params

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super().terminate()


@dataclass(frozen=True)
class IntentGuardTopoHandles:
    net: Mininet
    firewall: Node
    h_admin: Node
    h_eng: Node
    h_student: Node
    h_web: Node
    h_guest: Node


def build_intentguard_topology() -> IntentGuardTopoHandles:
    """Enterprise-style topology with central firewall.

    Zones:
      admin   -> 10.0.1.0/24
      eng     -> 10.0.2.0/24
      student -> 10.0.3.0/24
      dmz     -> 10.0.4.0/24 (web)
      guest   -> 10.0.5.0/24
    """

    net = Mininet(link=TCLink, controller=None, autoSetMacs=True, autoStaticArp=True)

    firewall = net.addHost("firewall", cls=LinuxRouter)

    h_admin = net.addHost("h_admin", ip="10.0.1.10/24", defaultRoute="via 10.0.1.1")
    h_eng = net.addHost("h_eng", ip="10.0.2.10/24", defaultRoute="via 10.0.2.1")
    h_student = net.addHost("h_student", ip="10.0.3.10/24", defaultRoute="via 10.0.3.1")
    h_web = net.addHost("h_web", ip="10.0.4.10/24", defaultRoute="via 10.0.4.1")
    h_guest = net.addHost("h_guest", ip="10.0.5.10/24", defaultRoute="via 10.0.5.1")

    # one switch per zone for clarity
    s_admin = net.addSwitch("s_admin")
    s_eng = net.addSwitch("s_eng")
    s_student = net.addSwitch("s_student")
    s_dmz = net.addSwitch("s_dmz")
    s_guest = net.addSwitch("s_guest")

    net.addLink(h_admin, s_admin)
    net.addLink(firewall, s_admin, intfName2="fw-admin", params2={"ip": "10.0.1.1/24"})

    net.addLink(h_eng, s_eng)
    net.addLink(firewall, s_eng, intfName2="fw-eng", params2={"ip": "10.0.2.1/24"})

    net.addLink(h_student, s_student)
    net.addLink(firewall, s_student, intfName2="fw-student", params2={"ip": "10.0.3.1/24"})

    net.addLink(h_web, s_dmz)
    net.addLink(firewall, s_dmz, intfName2="fw-dmz", params2={"ip": "10.0.4.1/24"})

    net.addLink(h_guest, s_guest)
    net.addLink(firewall, s_guest, intfName2="fw-guest", params2={"ip": "10.0.5.1/24"})

    return IntentGuardTopoHandles(
        net=net,
        firewall=firewall,
        h_admin=h_admin,
        h_eng=h_eng,
        h_student=h_student,
        h_web=h_web,
        h_guest=h_guest,
    )


