"""
Unified Network Forensic Data Models for BeaconHunter.
Covers Packets, Flows, C2 Beaconing Statistics, DNS Tunneling/DGA Findings,
TLS JA3/JA3S Fingerprints, Communication Graph Nodes/Edges, and MITRE ATT&CK Alerts.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any


@dataclass
class PacketRecord:
    """Normalized packet representation extracted from PCAP/PCAPNG."""
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, DNS, TLS, HTTP, ICMP
    length: int
    tcp_flags: str = ""
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_rcode: Optional[int] = None
    dns_answers: List[str] = field(default_factory=list)
    tls_record_type: Optional[str] = None  # ClientHello, ServerHello
    tls_version: Optional[int] = None
    tls_ciphers: List[int] = field(default_factory=list)
    tls_extensions: List[int] = field(default_factory=list)
    tls_elliptic_curves: List[int] = field(default_factory=list)
    tls_ec_point_formats: List[int] = field(default_factory=list)
    tls_sni: Optional[str] = None
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    http_user_agent: Optional[str] = None
    payload_size: int = 0


@dataclass
class BeaconFinding:
    """Statistical C2 Beaconing detection result for a directional network flow."""
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int
    total_bytes: int
    first_seen: float
    last_seen: float
    duration_seconds: float
    mean_interval: float
    median_interval: float
    std_dev: float
    mad_interval: float  # Median Absolute Deviation
    jitter_percent: float
    cv_ratio: float  # Coefficient of Variation (std_dev / mean_interval)
    periodicity_score: float  # 0.0 to 100.0
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    suspected_framework: str  # e.g., Cobalt Strike, Sliver, Mythic, Custom C2
    intervals: List[float] = field(default_factory=list)
    sni_or_host: str = ""
    ja3_hash: str = ""
    mitre_technique_id: str = "T1071.001"
    mitre_tactic: str = "Command and Control"
    description: str = ""


@dataclass
class DNSFinding:
    """DNS Forensics finding: Tunneling / Exfiltration or DGA Domain."""
    finding_type: str  # "DNS_TUNNELING" | "DGA_ACTIVITY" | "DNS_BURST"
    src_ip: str
    dst_ip: str
    base_domain: str
    sample_queries: List[str]
    query_count: int
    unique_subdomains: int
    nxdomain_count: int
    max_subdomain_length: int
    avg_shannon_entropy: float
    max_shannon_entropy: float
    encoding_detected: str  # Base64, Hex, Base32, High-Entropy Random, Consonant-Heavy DGA
    dga_probability: float  # 0.0 to 100.0
    query_rate_per_min: float
    total_exfil_bytes_est: int
    first_seen: float
    last_seen: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_technique_id: str  # T1071.004, T1568.002, T1048.003
    mitre_tactic: str
    description: str


@dataclass
class JA3Finding:
    """TLS JA3 / JA3S Fingerprint extraction and threat intelligence correlation."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    fingerprint_type: str  # "JA3" (Client) or "JA3S" (Server)
    ja3_string: str
    ja3_hash: str
    sni: str
    tls_version_name: str
    is_malicious: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, INFO
    matched_signature: str  # e.g., "Cobalt Strike Malleable C2", "Sliver Implant", "Tor Client"
    malware_family: str
    mitre_technique_id: str = "T1573.002"
    mitre_tactic: str = "Command and Control"
    description: str = ""


@dataclass
class ThreatAlert:
    """Unified high-level forensic alert correlated across modules."""
    alert_id: str
    timestamp: float
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # C2_BEACONING, DNS_TUNNELING, DGA_DETECTION, MALICIOUS_JA3
    title: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    indicator: str  # IP:Port, Domain, or JA3 Hash
    confidence: float  # 0-100%
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    evidence_summary: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphNode:
    """Node in the suspicious network communication topology."""
    node_id: str
    label: str
    node_type: str  # INTERNAL_HOST, C2_SERVER, DNS_SERVER, DGA_DOMAIN, EXFIL_DOMAIN, EXTERNAL_HOST
    risk_score: float  # 0 to 100
    severity: str
    alerts_count: int = 0
    total_bytes: int = 0
    details: str = ""


@dataclass
class GraphEdge:
    """Directed edge representing communication between two network entities."""
    source: str
    target: str
    protocol: str
    port: int
    packet_count: int
    byte_volume: int
    relationship: str  # e.g., "C2 Beacon (60s / 11% jitter)", "DNS Tunneling", "DGA Query", "TLS JA3 Match"
    severity: str
    is_suspicious: bool = False


@dataclass
class ForensicAnalysisReport:
    """Complete container for all results of a PCAP threat hunting scan."""
    pcap_path: str
    pcap_sha256: str
    file_size_bytes: int
    analysis_timestamp_utc: str
    total_packets: int
    capture_start_time: float
    capture_end_time: float
    capture_duration_seconds: float
    protocol_breakdown: Dict[str, int]
    beacons: List[BeaconFinding]
    dns_findings: List[DNSFinding]
    ja3_findings: List[JA3Finding]
    alerts: List[ThreatAlert]
    graph_nodes: List[GraphNode]
    graph_edges: List[GraphEdge]
