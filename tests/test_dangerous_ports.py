import unittest

from rules_recertify.reporting.dangerous_ports import dangerous_ports


class DangerousPortsTest(unittest.TestCase):
    def test_selected_catalogs_intersect_single_ports_and_ranges(self):
        self.assertEqual(
            dangerous_ports(
                "22 TCP;136-140 TCP;160-161 UDP;5903-5910 TCP",
                ["PORTS_TO_CONTROL", "PORTS_TO_ERADICATE"],
            ),
            "TCP/22, TCP/137-138, UDP/161, TCP/139, TCP/5903-5906",
        )

    def test_all_services_contains_every_selected_dangerous_definition(self):
        value = dangerous_ports("All Services", ["PORTS_TO_CONTROL"])
        self.assertEqual(
            value,
            "TCP/22, TCP/135, TCP/137-138, TCP/389, TCP/445, TCP/3268, "
            "TCP/3389, UDP/69, UDP/161",
        )

    def test_admin_catalog_and_protocol_slash_input(self):
        self.assertEqual(
            dangerous_ports("TCP/22;UDP/1434;TCP/1520-1522", ["PORTS_ADMIN"]),
            "TCP/1521-1522, UDP/1434, TCP/22",
        )

    def test_non_matching_and_portless_services_are_empty(self):
        self.assertEqual(dangerous_ports("443 TCP;0 ICMP", ["PORTS_TO_ERADICATE"]), "")
