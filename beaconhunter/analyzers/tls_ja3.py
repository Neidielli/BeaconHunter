"""
TLS JA3 & JA3S Fingerprinting Engine (Salesforce Specification).
Computes deterministic MD5 fingerprints of TLS ClientHello (JA3) and ServerHello (JA3S)
packets to identify malicious C2 implants (Cobalt Strike, Sliver, Mythic, Metasploit,
AsyncRAT, TrickBot, Tor) even over encrypted HTTPS/mTLS channels.

JA3 Format:
  SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
JA3S Format:
  SSLVersion,Cipher,SSLExtension
"""

import hashlib
from typing import List, Dict, Tuple

from beaconhunter.models import PacketRecord, JA3Finding
from beaconhunter.mitre import lookup_ja3, JA3_BENIGN_DB


TLS_VERSION_NAMES = {
    0x0300: "SSLv3 (768)",
    0x0301: "TLS 1.0 (769)",
    0x0302: "TLS 1.1 (770)",
    0x0303: "TLS 1.2 (771)",
    0x0304: "TLS 1.3 (772)",
}


def compute_ja3_string(pkt: PacketRecord) -> str:
    """
    Builds the canonical JA3 string from a TLS ClientHello packet:
    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    """
    ver = str(pkt.tls_version or 771)
    ciphers = "-".join(str(c) for c in pkt.tls_ciphers)
    exts = "-".join(str(e) for e in pkt.tls_extensions)
    curves = "-".join(str(g) for g in pkt.tls_elliptic_curves)
    formats = "-".join(str(f) for f in pkt.tls_ec_point_formats)
    return f"{ver},{ciphers},{exts},{curves},{formats}"


def compute_ja3s_string(pkt: PacketRecord) -> str:
    """
    Builds the canonical JA3S string from a TLS ServerHello packet:
    SSLVersion,Cipher,Extensions
    """
    ver = str(pkt.tls_version or 771)
    cipher = "-".join(str(c) for c in pkt.tls_ciphers)
    exts = "-".join(str(e) for e in pkt.tls_extensions)
    return f"{ver},{cipher},{exts}"


def extract_tls_fingerprints(packets: List[PacketRecord]) -> List[JA3Finding]:
    """
    Scans all TLS ClientHello and ServerHello packets, generates JA3 and JA3S
    MD5 hashes, and correlates them against the Threat Intelligence signature database.
    Deduplicates identical (src_ip, dst_ip, dst_port, ja3_hash) tuples while preserving earliest timestamp.
    """
    findings: List[JA3Finding] = []
    seen_tuples: Dict[Tuple[str, str, int, str], JA3Finding] = {}

    for pkt in packets:
        if pkt.protocol != "TLS" or not pkt.tls_record_type:
            continue

        if pkt.tls_record_type == "ClientHello":
            fp_type = "JA3"
            ja3_str = compute_ja3_string(pkt)
        elif pkt.tls_record_type == "ServerHello":
            fp_type = "JA3S"
            ja3_str = compute_ja3s_string(pkt)
        else:
            continue

        ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
        service_port = pkt.src_port if fp_type == "JA3S" else pkt.dst_port
        dedup_key = (pkt.src_ip, pkt.dst_ip, service_port, ja3_hash)
        if dedup_key in seen_tuples:
            continue

        ver_name = TLS_VERSION_NAMES.get(pkt.tls_version or 0x0303, f"TLS ({pkt.tls_version})")
        sni = pkt.tls_sni or "N/A (No SNI / Direct IP TLS)"

        threat_match = lookup_ja3(ja3_hash)
        if threat_match:
            is_malicious = True
            severity = threat_match["severity"]
            signature = threat_match["signature"]
            family = threat_match["family"]
            desc = (
                f"{fp_type} hash {ja3_hash} on {pkt.src_ip}:{pkt.src_port} -> "
                f"{pkt.dst_ip}:{pkt.dst_port} (SNI: {sni}) matches known threat signature: "
                f"{signature}. {threat_match['description']}"
            )
        elif pkt.tls_record_type == "ClientHello" and not pkt.tls_sni:
            # Direct IP HTTPS connection without SNI header is a strong C2 indicator
            is_malicious = True
            severity = "MEDIUM"
            signature = "Anomalous TLS ClientHello without SNI Extension (Direct IP C2)"
            family = "Suspicious Custom TLS Client"
            desc = (
                f"TLS ClientHello from {pkt.src_ip} to {pkt.dst_ip}:{pkt.dst_port} omitted the "
                f"Server Name Indication (SNI) extension (JA3: {ja3_hash}), typical of direct-IP C2 implants."
            )
        else:
            is_malicious = False
            severity = "INFO"
            benign_label = JA3_BENIGN_DB.get(ja3_hash, "Unclassified / Standard TLS Stack")
            signature = benign_label
            family = "Benign / Standard"
            desc = f"Standard {fp_type} fingerprint ({ja3_hash}) observed for SNI: {sni}."

        finding = JA3Finding(
            timestamp=pkt.timestamp,
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            fingerprint_type=fp_type,
            ja3_string=ja3_str,
            ja3_hash=ja3_hash,
            sni=sni,
            tls_version_name=ver_name,
            is_malicious=is_malicious,
            severity=severity,
            matched_signature=signature,
            malware_family=family,
            mitre_technique_id="T1573.002",
            mitre_tactic="Command and Control",
            description=desc,
        )
        seen_tuples[dedup_key] = finding
        findings.append(finding)

    # Sort malicious findings first
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    findings.sort(
        key=lambda f: (f.is_malicious, severity_rank.get(f.severity, 0)),
        reverse=True,
    )
    return findings
