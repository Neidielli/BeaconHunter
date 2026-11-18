"""
Network Topology Graph Builder & Unified Threat Alert Correlator.
Constructs a directed graph of suspicious communication nodes (Internal Compromised Hosts,
C2 Servers, DNS Resolvers, Exfiltration Domains, DGA Clusters) and edges, and orchestrates
the complete forensic pipeline.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple

from beaconhunter.models import (
    PacketRecord,
    BeaconFinding,
    DNSFinding,
    JA3Finding,
    ThreatAlert,
    GraphNode,
    GraphEdge,
    ForensicAnalysisReport,
)
from beaconhunter.mitre import get_mitre_info
from beaconhunter.pcap_engine import compute_file_sha256, load_and_dissect_pcap
from beaconhunter.analyzers.beaconing import detect_c2_beaconing
from beaconhunter.analyzers.dns_forensics import analyze_dns_traffic
from beaconhunter.analyzers.tls_ja3 import extract_tls_fingerprints


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def is_private_ip(ip_addr: str) -> bool:
    """Checks if an IPv4 address belongs to RFC1918 private network ranges."""
    return (
        ip_addr.startswith("10.")
        or ip_addr.startswith("192.168.")
        or ip_addr.startswith("127.")
        or any(ip_addr.startswith(f"172.{i}.") for i in range(16, 32))
    )


def correlate_alerts_and_build_graph(
    packets: List[PacketRecord],
    beacons: List[BeaconFinding],
    dns_findings: List[DNSFinding],
    ja3_findings: List[JA3Finding],
) -> Tuple[List[ThreatAlert], List[GraphNode], List[GraphEdge]]:
    """
    Generates unified MITRE ATT&CK ThreatAlert objects and builds the suspicious
    communication graph (nodes & edges) for CSV, DOT, and Interactive HTML visualization.
    """
    alerts: List[ThreatAlert] = []
    nodes_map: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []

    alert_counter = 1

    def ensure_node(
        node_id: str,
        label: str,
        node_type: str,
        risk: float,
        severity: str,
        bytes_delta: int = 0,
        detail: str = "",
        increment_alert: bool = True,
    ) -> None:
        if node_id not in nodes_map:
            nodes_map[node_id] = GraphNode(
                node_id=node_id,
                label=label,
                node_type=node_type,
                risk_score=risk,
                severity=severity,
                alerts_count=1 if increment_alert else 0,
                total_bytes=bytes_delta,
                details=detail,
            )
        else:
            existing = nodes_map[node_id]
            existing.risk_score = max(existing.risk_score, risk)
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(existing.severity, 0):
                existing.severity = severity
            if increment_alert:
                existing.alerts_count += 1
            existing.total_bytes += bytes_delta
            if detail and detail not in existing.details:
                existing.details = f"{existing.details} | {detail}" if existing.details else detail

    # 1. Process C2 Beaconing Findings
    for b in beacons:
        mitre = get_mitre_info(b.mitre_technique_id)
        alerts.append(
            ThreatAlert(
                alert_id=f"BH-C2-{alert_counter:03d}",
                timestamp=b.first_seen,
                severity=b.severity,
                category="C2_BEACONING",
                title=f"C2 Beaconing Detected: {b.suspected_framework}",
                src_ip=b.src_ip,
                dst_ip=b.dst_ip,
                dst_port=b.dst_port,
                protocol=b.protocol,
                indicator=f"{b.dst_ip}:{b.dst_port}" + (f" ({b.sni_or_host})" if b.sni_or_host else ""),
                confidence=b.periodicity_score,
                mitre_tactic=mitre["tactic"],
                mitre_technique_id=mitre["id"],
                mitre_technique_name=mitre["name"],
                evidence_summary=b.description,
                metadata={
                    "mean_interval": b.mean_interval,
                    "jitter_percent": b.jitter_percent,
                    "cv_ratio": b.cv_ratio,
                    "packet_count": b.packet_count,
                    "ja3_hash": b.ja3_hash,
                },
            )
        )
        alert_counter += 1

        ensure_node(
            b.src_ip,
            f"Host {b.src_ip}",
            "INTERNAL_HOST" if is_private_ip(b.src_ip) else "EXTERNAL_HOST",
            b.periodicity_score,
            b.severity,
            b.total_bytes,
            f"Compromised Beaconing Host ({b.src_ip})",
        )
        c2_label = f"{b.dst_ip}:{b.dst_port}" + (f"\n({b.sni_or_host})" if b.sni_or_host else "")
        ensure_node(
            b.dst_ip,
            c2_label,
            "C2_SERVER",
            b.periodicity_score,
            b.severity,
            b.total_bytes,
            b.suspected_framework,
        )
        edges.append(
            GraphEdge(
                source=b.src_ip,
                target=b.dst_ip,
                protocol=b.protocol,
                port=b.dst_port,
                packet_count=b.packet_count,
                byte_volume=b.total_bytes,
                relationship=f"C2 Beacon ({b.mean_interval}s / {b.jitter_percent}% jitter)",
                severity=b.severity,
                is_suspicious=True,
            )
        )

    # 2. Process DNS Forensics Findings (Tunneling & DGA)
    for d in dns_findings:
        mitre = get_mitre_info(d.mitre_technique_id)
        is_dga = d.finding_type == "DGA_ACTIVITY"
        cat = "DGA_DETECTION" if is_dga else "DNS_TUNNELING"
        title = (
            f"DGA Domain Generation Burst ({d.unique_subdomains} domains)"
            if is_dga
            else f"DNS Tunneling & Exfiltration ({d.base_domain})"
        )
        conf = d.dga_probability if is_dga else min(99.0, round(d.avg_shannon_entropy * 22.0, 1))

        alerts.append(
            ThreatAlert(
                alert_id=f"BH-DNS-{alert_counter:03d}",
                timestamp=d.first_seen,
                severity=d.severity,
                category=cat,
                title=title,
                src_ip=d.src_ip,
                dst_ip=d.dst_ip,
                dst_port=53,
                protocol="DNS",
                indicator=d.base_domain,
                confidence=conf,
                mitre_tactic=mitre["tactic"],
                mitre_technique_id=mitre["id"],
                mitre_technique_name=mitre["name"],
                evidence_summary=d.description,
                metadata={
                    "avg_entropy": d.avg_shannon_entropy,
                    "max_entropy": d.max_shannon_entropy,
                    "encoding": d.encoding_detected,
                    "query_count": d.query_count,
                    "unique_subdomains": d.unique_subdomains,
                    "exfil_bytes_est": d.total_exfil_bytes_est,
                },
            )
        )
        alert_counter += 1

        ensure_node(
            d.src_ip,
            f"Host {d.src_ip}",
            "INTERNAL_HOST" if is_private_ip(d.src_ip) else "EXTERNAL_HOST",
            conf,
            d.severity,
            d.total_exfil_bytes_est,
            f"Origin of {cat}",
        )
        ensure_node(
            d.dst_ip,
            f"DNS {d.dst_ip}",
            "DNS_SERVER",
            40.0,
            "MEDIUM",
            0,
            "DNS Resolver",
            increment_alert=False,
        )

        target_node_id = f"DOM:{d.base_domain}"
        target_type = "DGA_DOMAIN" if is_dga else "EXFIL_DOMAIN"
        ensure_node(
            target_node_id,
            d.base_domain,
            target_type,
            conf,
            d.severity,
            d.total_exfil_bytes_est,
            d.encoding_detected,
        )

        # Edge from Host -> DNS Server -> Suspicious Domain Cluster
        edges.append(
            GraphEdge(
                source=d.src_ip,
                target=target_node_id,
                protocol="DNS",
                port=53,
                packet_count=d.query_count,
                byte_volume=d.total_exfil_bytes_est or (d.query_count * 90),
                relationship=(
                    f"DGA Burst ({d.unique_subdomains} doms, H={d.avg_shannon_entropy})"
                    if is_dga
                    else f"DNS Tunnel (H={d.avg_shannon_entropy} bits, ~{d.total_exfil_bytes_est}B)"
                ),
                severity=d.severity,
                is_suspicious=True,
            )
        )

    # 3. Process Malicious TLS JA3 / JA3S Findings
    for j in ja3_findings:
        if not j.is_malicious:
            continue
        mitre = get_mitre_info(j.mitre_technique_id)
        alerts.append(
            ThreatAlert(
                alert_id=f"BH-JA3-{alert_counter:03d}",
                timestamp=j.timestamp,
                severity=j.severity,
                category="MALICIOUS_JA3",
                title=f"Malicious TLS {j.fingerprint_type}: {j.matched_signature}",
                src_ip=j.src_ip,
                dst_ip=j.dst_ip,
                dst_port=j.dst_port,
                protocol="TLS",
                indicator=f"{j.ja3_hash} ({j.malware_family})",
                confidence=95.0 if j.severity == "CRITICAL" else 80.0,
                mitre_tactic=mitre["tactic"],
                mitre_technique_id=mitre["id"],
                mitre_technique_name=mitre["name"],
                evidence_summary=j.description,
                metadata={
                    "ja3_hash": j.ja3_hash,
                    "ja3_string": j.ja3_string,
                    "sni": j.sni,
                    "malware_family": j.malware_family,
                },
            )
        )
        alert_counter += 1

        # Ensure nodes exist in graph if not already created by beaconing
        client_ip = j.src_ip if j.fingerprint_type == "JA3" else j.dst_ip
        server_ip = j.dst_ip if j.fingerprint_type == "JA3" else j.src_ip
        ensure_node(
            client_ip,
            f"Host {client_ip}",
            "INTERNAL_HOST" if is_private_ip(client_ip) else "EXTERNAL_HOST",
            90.0,
            j.severity,
            0,
            f"TLS Client ({j.malware_family})",
        )
        ensure_node(
            server_ip,
            f"{server_ip}\n({j.malware_family})",
            "C2_SERVER",
            95.0,
            j.severity,
            0,
            j.matched_signature,
        )

        # Add JA3 edge if no C2 beacon edge already links client_ip -> server_ip
        has_edge = any(e.source == client_ip and e.target == server_ip for e in edges)
        if not has_edge:
            edges.append(
                GraphEdge(
                    source=client_ip,
                    target=server_ip,
                    protocol="TLS",
                    port=j.dst_port,
                    packet_count=1,
                    byte_volume=256,
                    relationship=f"{j.fingerprint_type}: {j.malware_family} ({j.ja3_hash[:10]}...)",
                    severity=j.severity,
                    is_suspicious=True,
                )
            )

    alerts.sort(
        key=lambda a: (SEVERITY_ORDER.get(a.severity, 0), a.confidence),
        reverse=True,
    )
    nodes_list = sorted(nodes_map.values(), key=lambda n: n.risk_score, reverse=True)
    return alerts, nodes_list, edges


def run_full_pcap_analysis(pcap_path: Path) -> ForensicAnalysisReport:
    """
    Executes the end-to-end network forensic threat hunting pipeline on a PCAP/PCAPNG file.
    """
    pcap_path = Path(pcap_path).resolve()
    file_size = pcap_path.stat().st_size
    sha256_hash = compute_file_sha256(pcap_path)

    packets, proto_counts = load_and_dissect_pcap(pcap_path)
    if packets:
        start_ts = min(p.timestamp for p in packets)
        end_ts = max(p.timestamp for p in packets)
        duration = round(end_ts - start_ts, 2)
    else:
        start_ts = 0.0
        end_ts = 0.0
        duration = 0.0

    # 1. Extract TLS JA3 / JA3S Fingerprints first (used to enrich C2 Beaconing)
    ja3_findings = extract_tls_fingerprints(packets)

    # 2. Run Statistical C2 Beaconing Detection
    beacons = detect_c2_beaconing(packets, ja3_findings)

    # 3. Run DNS Tunneling / Exfiltration & DGA Detection
    dns_findings = analyze_dns_traffic(packets)

    # 4. Correlate Threat Alerts & Build Suspicious Communication Graph
    alerts, graph_nodes, graph_edges = correlate_alerts_and_build_graph(
        packets, beacons, dns_findings, ja3_findings
    )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return ForensicAnalysisReport(
        pcap_path=str(pcap_path),
        pcap_sha256=sha256_hash,
        file_size_bytes=file_size,
        analysis_timestamp_utc=now_utc,
        total_packets=len(packets),
        capture_start_time=start_ts,
        capture_end_time=end_ts,
        capture_duration_seconds=duration,
        protocol_breakdown=proto_counts,
        beacons=beacons,
        dns_findings=dns_findings,
        ja3_findings=ja3_findings,
        alerts=alerts,
        graph_nodes=graph_nodes,
        graph_edges=graph_edges,
    )
