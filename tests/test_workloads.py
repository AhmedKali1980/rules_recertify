import unittest
from rules_recertify.resolution.workloads import matching_nz3, ocs_name_from_ip, parse_interfaces, select_addresses, short_hostname

class WorkloadTest(unittest.TestCase):
    def test_interfaces_are_parsed_and_deduplicated(self):
        ips,warnings=parse_interfaces("aut0:192.18.18.247; aut0:175.128.12.115; x:192.18.18.247; broken")
        self.assertEqual(ips,["192.18.18.247","175.128.12.115"]); self.assertEqual(len(warnings),1)
    def test_managed_uses_default_gateway_ip(self):
        self.assertEqual(select_addresses({"managed":"TRUE","ip_with_default_gw":"10.20.30.40"})[0],["10.20.30.40"])
    def test_enrichment(self):
        self.assertEqual(short_hostname("host.example.org"),"host")
        self.assertEqual(short_hostname(""),"[hostname_empty]")
        self.assertEqual(ocs_name_from_ip("10.20.30.40"),"10-20-30-40")
        self.assertEqual(matching_nz3("10.20.30.40", [{"name":"NZ3_A","include":"10.20.30.0/24"},{"name":"OTHER","include":"10.0.0.0/8"}]),[("NZ3_A","10.20.30.0/24")])
