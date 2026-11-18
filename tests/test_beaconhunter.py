"""
Unit & Integration Test Suite for BeaconHunter.
Verifies:
  1. Synthetic PCAP Generation & Dissection
  2. Statistical C2 Beaconing Detection (Cobalt Strike ~60s & Sliver ~15s)
  3. DNS Tunneling (Shannon Entropy + Base64) & DGA Spike Detection
  4. TLS JA3 & JA3S Extraction and Threat Signature Matching
  5. CSV, Graphviz DOT, Chain-of-Custody JSON & Interactive HTML Dashboard Export
"""

import tempfile
import unittest
from pathlib import Path

from beaconhunter.analyzers.dns_forensics import calculate_shannon_entropy, score_dga_domain
from beaconhunter.analyzers.graph_builder import run_full_pcap_analysis
from beaconhunter.exporters.csv_exporter import export_forensic_csv_suite
from beaconhunter.exporters.html_dashboard import generate_html_dashboard
from beaconhunter.simulator.pcap_generator import generate_synthetic_pcap


class TestBeaconHunterEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.base_path = Path(cls.temp_dir.name)
        cls.pcap_path = cls.base_path / "test_apt_capture.pcap"
        generate_synthetic_pcap(cls.pcap_path, seed=42)
        cls.report = run_full_pcap_analysis(cls.pcap_path)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def test_shannon_entropy_math(self) -> None:
        low_ent = calculate_shannon_entropy("aaaaaaaaaa")
        self.assertEqual(low_ent, 0.0)
        high_ent = calculate_shannon_entropy("aGVsbG8gd29ybGQxMjM0NTY3ODkw")
        self.assertGreater(high_ent, 4.0)

    def test_dga_scoring_heuristics(self) -> None:
        benign_score = score_dga_domain("microsoft")
        dga_score = score_dga_domain("xkq9v2m8zpl1w")
        self.assertLess(benign_score, 40.0)
        self.assertGreaterEqual(dga_score, 75.0)

    def test_c2_beaconing_detection(self) -> None:
        self.assertGreaterEqual(len(self.report.beacons), 2)
        dst_ips = {b.dst_ip for b in self.report.beacons}
        # Must detect both Cobalt Strike (185.220.101.34) and Sliver (45.77.120.88)
        self.assertIn("185.220.101.34", dst_ips)
        self.assertIn("45.77.120.88", dst_ips)
        for b in self.report.beacons:
            self.assertGreaterEqual(b.periodicity_score, 75.0)

    def test_dns_tunneling_and_dga_detection(self) -> None:
        finding_types = {d.finding_type for d in self.report.dns_findings}
        self.assertIn("DNS_TUNNELING", finding_types)
        self.assertIn("DGA_ACTIVITY", finding_types)

        tunnel = next(d for d in self.report.dns_findings if d.finding_type == "DNS_TUNNELING")
        self.assertEqual(tunnel.base_domain, "c2-shadow-ops.net")
        self.assertGreaterEqual(tunnel.avg_shannon_entropy, 3.8)
        self.assertGreater(tunnel.total_exfil_bytes_est, 200)

    def test_tls_ja3_and_ja3s_fingerprinting(self) -> None:
        malicious_ja3 = [j for j in self.report.ja3_findings if j.is_malicious]
        self.assertGreaterEqual(len(malicious_ja3), 4)
        families = {j.malware_family for j in malicious_ja3}
        self.assertIn("Cobalt Strike", families)
        self.assertIn("Sliver C2", families)

    def test_exporters_and_chain_of_custody(self) -> None:
        out_dir = self.base_path / "forensic_out"
        exported = export_forensic_csv_suite(self.report, out_dir)
        for key in (
            "threat_alerts_csv",
            "c2_beacons_csv",
            "dns_forensics_csv",
            "tls_ja3_csv",
            "network_graph_csv",
            "network_topology_dot",
            "evidence_manifest",
        ):
            self.assertIn(key, exported)
            self.assertTrue(exported[key].exists())
            self.assertGreater(exported[key].stat().st_size, 50)

        html_file = generate_html_dashboard(self.report, out_dir / "report.html")
        self.assertTrue(html_file.exists())
        html_text = html_file.read_text(encoding="utf-8")
        self.assertIn("BeaconHunter", html_text)
        self.assertIn("Cobalt Strike", html_text)
        self.assertIn("c2-shadow-ops.net", html_text)


if __name__ == "__main__":
    unittest.main()
