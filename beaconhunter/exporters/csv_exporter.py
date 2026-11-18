"""
Forensic CSV, Graphviz DOT & Chain-of-Custody JSON Exporter.
Generates court-ready and SIEM/Timeline Explorer-compatible CSV artifacts along with
an immutable SHA-256 evidence_manifest.json per ISO/IEC 27037 & RFC 3227 standards.
"""

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from beaconhunter.models import ForensicAnalysisReport
from beaconhunter.pcap_engine import compute_file_sha256


def export_forensic_csv_suite(
    report: ForensicAnalysisReport, output_dir: Path
) -> Dict[str, Path]:
    """
    Exports all forensic findings to structured CSV files, a Graphviz DOT network graph,
    and a cryptographic Chain of Custody manifest (evidence_manifest.json).
    """
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    exported_files: Dict[str, Path] = {}

    # 1. Unified MITRE ATT&CK Threat Alerts CSV
    alerts_csv = output_dir / "threat_alerts.csv"
    with open(alerts_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Alert_ID",
            "Timestamp_Epoch",
            "Timestamp_UTC",
            "Severity",
            "Category",
            "MITRE_Tactic",
            "MITRE_Technique_ID",
            "MITRE_Technique_Name",
            "Source_IP",
            "Destination_IP",
            "Destination_Port",
            "Protocol",
            "Indicator",
            "Confidence_Pct",
            "Title",
            "Evidence_Summary",
        ])
        for a in report.alerts:
            utc_str = datetime.fromtimestamp(a.timestamp, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3]
            writer.writerow([
                a.alert_id,
                f"{a.timestamp:.3f}",
                utc_str,
                a.severity,
                a.category,
                a.mitre_tactic,
                a.mitre_technique_id,
                a.mitre_technique_name,
                a.src_ip,
                a.dst_ip,
                a.dst_port,
                a.protocol,
                a.indicator,
                a.confidence,
                a.title,
                a.evidence_summary,
            ])
    exported_files["threat_alerts_csv"] = alerts_csv

    # 2. C2 Beaconing Analysis CSV
    beacons_csv = output_dir / "c2_beacons.csv"
    with open(beacons_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Flow_ID",
            "Severity",
            "Periodicity_Score",
            "Suspected_Framework",
            "Source_IP",
            "Destination_IP",
            "Destination_Port",
            "Protocol",
            "SNI_or_Host",
            "JA3_Hash",
            "Mean_Interval_Sec",
            "Median_Interval_Sec",
            "Std_Dev_Sec",
            "MAD_Interval_Sec",
            "Jitter_Percent",
            "CV_Ratio",
            "Packet_Count",
            "Total_Bytes",
            "Duration_Sec",
            "MITRE_Technique_ID",
            "Description",
        ])
        for b in report.beacons:
            writer.writerow([
                b.flow_id,
                b.severity,
                b.periodicity_score,
                b.suspected_framework,
                b.src_ip,
                b.dst_ip,
                b.dst_port,
                b.protocol,
                b.sni_or_host,
                b.ja3_hash,
                b.mean_interval,
                b.median_interval,
                b.std_dev,
                b.mad_interval,
                b.jitter_percent,
                b.cv_ratio,
                b.packet_count,
                b.total_bytes,
                b.duration_seconds,
                b.mitre_technique_id,
                b.description,
            ])
    exported_files["c2_beacons_csv"] = beacons_csv

    # 3. DNS Forensics (Tunneling / Exfiltration / DGA) CSV
    dns_csv = output_dir / "dns_forensics.csv"
    with open(dns_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Finding_Type",
            "Severity",
            "Source_IP",
            "DNS_Server_IP",
            "Base_Domain",
            "Query_Count",
            "Unique_Subdomains",
            "NXDOMAIN_Count",
            "Avg_Shannon_Entropy",
            "Max_Shannon_Entropy",
            "Max_Subdomain_Length",
            "Encoding_Detected",
            "DGA_Probability_Pct",
            "Query_Rate_Per_Min",
            "Est_Exfil_Bytes",
            "MITRE_Technique_ID",
            "Sample_Queries",
            "Description",
        ])
        for d in report.dns_findings:
            writer.writerow([
                d.finding_type,
                d.severity,
                d.src_ip,
                d.dst_ip,
                d.base_domain,
                d.query_count,
                d.unique_subdomains,
                d.nxdomain_count,
                d.avg_shannon_entropy,
                d.max_shannon_entropy,
                d.max_subdomain_length,
                d.encoding_detected,
                d.dga_probability,
                d.query_rate_per_min,
                d.total_exfil_bytes_est,
                d.mitre_technique_id,
                " | ".join(d.sample_queries[:5]),
                d.description,
            ])
    exported_files["dns_forensics_csv"] = dns_csv

    # 4. TLS JA3 / JA3S Fingerprints CSV
    ja3_csv = output_dir / "tls_ja3_fingerprints.csv"
    with open(ja3_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Fingerprint_Type",
            "Severity",
            "Is_Malicious",
            "Malware_Family",
            "Matched_Signature",
            "JA3_MD5_Hash",
            "SNI",
            "TLS_Version",
            "Source_IP",
            "Source_Port",
            "Destination_IP",
            "Destination_Port",
            "JA3_Raw_String",
            "MITRE_Technique_ID",
        ])
        for j in report.ja3_findings:
            writer.writerow([
                j.fingerprint_type,
                j.severity,
                j.is_malicious,
                j.malware_family,
                j.matched_signature,
                j.ja3_hash,
                j.sni,
                j.tls_version_name,
                j.src_ip,
                j.src_port,
                j.dst_ip,
                j.dst_port,
                j.ja3_string,
                j.mitre_technique_id,
            ])
    exported_files["tls_ja3_csv"] = ja3_csv

    # 5. Suspicious Network Graph Edges CSV & Graphviz DOT
    edges_csv = output_dir / "network_graph_edges.csv"
    with open(edges_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Source_Node",
            "Target_Node",
            "Protocol",
            "Port",
            "Severity",
            "Packet_Count",
            "Byte_Volume",
            "Relationship",
        ])
        for e in report.graph_edges:
            writer.writerow([
                e.source,
                e.target,
                e.protocol,
                e.port,
                e.severity,
                e.packet_count,
                e.byte_volume,
                e.relationship,
            ])
    exported_files["network_graph_csv"] = edges_csv

    dot_path = output_dir / "network_topology.dot"
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write("digraph BeaconHunter_Topology {\n")
        f.write('  rankdir=LR;\n  bgcolor="#0b0f19";\n')
        f.write('  node [style="filled,rounded", shape=box, fontname="Consolas", fontcolor="#e2e8f0"];\n')
        f.write('  edge [fontname="Consolas", fontsize=10, fontcolor="#94a3b8"];\n\n')
        for n in report.graph_nodes:
            color = "#ff0055" if n.severity == "CRITICAL" else ("#ff9900" if n.severity == "HIGH" else "#00e5ff")
            f.write(
                f'  "{n.node_id}" [label="{n.label}\\n[{n.node_type} | Risk: {n.risk_score}]", '
                f'fillcolor="#161f33", color="{color}", penwidth=2];\n'
            )
        f.write("\n")
        for e in report.graph_edges:
            ecolor = "#ff0055" if e.severity == "CRITICAL" else "#00ff66"
            f.write(
                f'  "{e.source}" -> "{e.target}" [label="{e.relationship}", color="{ecolor}", penwidth=1.8];\n'
            )
        f.write("}\n")
    exported_files["network_topology_dot"] = dot_path

    # 6. Chain of Custody Manifest (ISO/IEC 27037 & RFC 3227 Compliance)
    manifest_path = output_dir / "evidence_manifest.json"
    artifact_hashes = {
        name: {
            "path": str(p),
            "sha256": compute_file_sha256(p),
            "size_bytes": p.stat().st_size,
        }
        for name, p in exported_files.items()
    }
    manifest_data = {
        "tool": "BeaconHunter — PCAP Network Threat & C2 Beaconing Detector",
        "version": "1.0.0",
        "compliance_standards": [
            "RFC 3227 (Guidelines for Evidence Collection and Archiving)",
            "ISO/IEC 27037:2012 (Digital Evidence Identification & Preservation)",
            "NIST SP 800-86 (Forensic Techniques into Incident Response)",
        ],
        "source_evidence": {
            "pcap_path": report.pcap_path,
            "sha256_checksum": report.pcap_sha256,
            "file_size_bytes": report.file_size_bytes,
            "total_packets_analyzed": report.total_packets,
            "capture_duration_seconds": report.capture_duration_seconds,
        },
        "analysis_timestamp_utc": report.analysis_timestamp_utc,
        "summary_counts": {
            "total_alerts": len(report.alerts),
            "c2_beacons_detected": len(report.beacons),
            "dns_anomalies_detected": len(report.dns_findings),
            "malicious_ja3_fingerprints": sum(1 for j in report.ja3_findings if j.is_malicious),
            "suspicious_graph_nodes": len(report.graph_nodes),
        },
        "generated_forensic_artifacts": artifact_hashes,
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
    exported_files["evidence_manifest"] = manifest_path

    return exported_files
