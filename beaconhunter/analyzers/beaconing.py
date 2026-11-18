"""
Statistical C2 Beaconing Detector (Cobalt Strike, Sliver, Mythic, Custom RATs).
Analyzes inter-arrival times (delta-t) of outbound TCP/HTTP/TLS sessions using:
  - Mean Interval (mu) & Median Interval
  - Standard Deviation (sigma) & Coefficient of Variation (CV = sigma / mu)
  - Median Absolute Deviation (MAD) for outlier-resilient periodicity scoring
  - Jitter Percentage estimation
"""

import math
import statistics
from collections import defaultdict
from typing import List, Dict, Tuple

from beaconhunter.models import PacketRecord, BeaconFinding, JA3Finding


NON_STANDARD_C2_PORTS = {4444, 8443, 8080, 8888, 1337, 9001, 50050, 2222}


def _filter_heartbeat_timestamps(timestamps: List[float], min_burst_gap: float = 0.85) -> List[float]:
    """
    Collapses sub-second packet bursts belonging to the same TCP handshake / TLS record
    exchange into a single logical connection/beacon event timestamp.
    """
    if not timestamps:
        return []
    sorted_ts = sorted(timestamps)
    logical_events = [sorted_ts[0]]
    for ts in sorted_ts[1:]:
        if (ts - logical_events[-1]) >= min_burst_gap:
            logical_events.append(ts)
    return logical_events


def _classify_c2_profile(
    mean_interval: float,
    jitter_pct: float,
    dst_port: int,
    protocol: str,
    ja3_family: str,
) -> Tuple[str, str]:
    """
    Infers the likely C2 framework or implant profile from statistical timing,
    port selection, and optional JA3 fingerprint match.
    """
    if ja3_family:
        return (
            f"{ja3_family} Beacon ({mean_interval:.1f}s ± {jitter_pct:.1f}% jitter)",
            "T1071.001" if dst_port in (80, 443, 8080, 8443) else "T1571",
        )

    if 50.0 <= mean_interval <= 70.0 and jitter_pct <= 25.0:
        return (
            f"Cobalt Strike Malleable C2 Profile (~60s sleep / {jitter_pct:.1f}% jitter)",
            "T1071.001",
        )
    if 12.0 <= mean_interval <= 35.0 and dst_port in (8443, 8888, 443):
        return (
            f"Sliver / Mythic C2 Implant (~{mean_interval:.0f}s heartbeat / {jitter_pct:.1f}% jitter)",
            "T1571" if dst_port not in (80, 443) else "T1071.001",
        )
    if 1.0 <= mean_interval < 12.0 and jitter_pct <= 20.0:
        return (
            f"Fast-Polling Interactive RAT / Reverse Shell ({mean_interval:.1f}s sleep)",
            "T1571" if dst_port in NON_STANDARD_C2_PORTS else "T1071.001",
        )
    return (
        f"Periodic Automated C2 Beacon ({mean_interval:.1f}s interval / {jitter_pct:.1f}% jitter)",
        "T1071.001",
    )


def detect_c2_beaconing(
    packets: List[PacketRecord],
    ja3_findings: List[JA3Finding],
    min_beacon_events: int = 6,
) -> List[BeaconFinding]:
    """
    Analyzes directional flows (src_ip -> dst_ip:dst_port) to identify periodic
    C2 beaconing behavior even in the presence of configured randomized jitter.
    """
    # Map (src_ip, dst_ip, dst_port) -> JA3 metadata if available
    flow_ja3_map: Dict[Tuple[str, str, int], JA3Finding] = {}
    for jf in ja3_findings:
        if jf.fingerprint_type == "JA3":
            key = (jf.src_ip, jf.dst_ip, jf.dst_port)
            if key not in flow_ja3_map or jf.is_malicious:
                flow_ja3_map[key] = jf

    # Group outbound client-to-server packets by (src_ip, dst_ip, dst_port)
    # Exclude pure DNS port 53 (handled by DNS Forensics module) and ephemeral source ports
    flows: Dict[Tuple[str, str, int], List[PacketRecord]] = defaultdict(list)

    for pkt in packets:
        if pkt.protocol == "DNS" or pkt.dst_port == 53 or pkt.src_port == 53:
            continue
        # Only track client -> server direction (where dst_port is a service port < 50000 or known C2 port)
        if pkt.dst_port > 0 and (pkt.dst_port < 49152 or pkt.dst_port in NON_STANDARD_C2_PORTS):
            flows[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)

    findings: List[BeaconFinding] = []

    for (src_ip, dst_ip, dst_port), flow_pkts in flows.items():
        raw_timestamps = [p.timestamp for p in flow_pkts]
        logical_ts = _filter_heartbeat_timestamps(raw_timestamps, min_burst_gap=0.85)

        if len(logical_ts) < min_beacon_events:
            continue

        # Compute inter-arrival intervals (delta_t)
        intervals = [
            round(logical_ts[i] - logical_ts[i - 1], 4)
            for i in range(1, len(logical_ts))
        ]
        if not intervals:
            continue

        mean_int = statistics.mean(intervals)
        if mean_int <= 0.2:
            continue

        median_int = statistics.median(intervals)
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv_ratio = std_dev / mean_int if mean_int > 0 else 999.0

        # Median Absolute Deviation (MAD)
        abs_devs = [abs(x - median_int) for x in intervals]
        mad_int = statistics.median(abs_devs) if abs_devs else 0.0
        mad_norm = mad_int / median_int if median_int > 0 else 999.0

        # Estimate Jitter % (average relative deviation from median interval)
        avg_abs_dev = statistics.mean(abs_devs) if abs_devs else 0.0
        jitter_pct = min(100.0, (avg_abs_dev / median_int) * 100.0) if median_int > 0 else 100.0

        # Calculate Composite Periodicity Score (0 - 100)
        # 1. CV Component (low CV = high regularity; CV <= 0.30 is typical for 0-30% jitter C2)
        cv_score = max(0.0, 100.0 * (1.0 - (cv_ratio / 0.55)))
        # 2. MAD Component (resilient to occasional network hiccups)
        mad_score = max(0.0, 100.0 * (1.0 - (mad_norm / 0.45)))
        # 3. Sample Size Bonus (more heartbeats = higher statistical confidence)
        count_bonus = min(12.0, (len(logical_ts) - min_beacon_events) * 1.2)

        raw_score = (0.50 * cv_score) + (0.50 * mad_score) + count_bonus

        # Enrich with JA3 / SNI / HTTP Host
        ja3_match = flow_ja3_map.get((src_ip, dst_ip, dst_port))
        ja3_hash = ja3_match.ja3_hash if ja3_match else ""
        ja3_family = ja3_match.malware_family if (ja3_match and ja3_match.is_malicious) else ""

        if ja3_family:
            raw_score = min(100.0, raw_score + 15.0)
        if dst_port in NON_STANDARD_C2_PORTS:
            raw_score = min(100.0, raw_score + 5.0)

        periodicity_score = round(min(100.0, max(0.0, raw_score)), 1)

        # Only flag flows with periodicity_score >= 60.0 (meaning strong regularity / controlled jitter)
        if periodicity_score < 60.0:
            continue

        # Determine dominant application protocol & SNI/Host
        app_proto = "TCP"
        sni_or_host = ""
        for p in flow_pkts:
            if p.protocol in ("TLS", "HTTP"):
                app_proto = p.protocol
            if p.tls_sni and not sni_or_host:
                sni_or_host = p.tls_sni
            elif p.http_host and not sni_or_host:
                sni_or_host = p.http_host

        if periodicity_score >= 85.0 or ja3_family:
            severity = "CRITICAL"
        elif periodicity_score >= 75.0:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        framework_label, mitre_id = _classify_c2_profile(
            mean_int, jitter_pct, dst_port, app_proto, ja3_family
        )

        total_bytes = sum(p.length for p in flow_pkts)
        first_seen = logical_ts[0]
        last_seen = logical_ts[-1]
        duration = round(last_seen - first_seen, 2)

        desc = (
            f"Detected {len(logical_ts)} periodic {app_proto} heartbeats from {src_ip} to "
            f"{dst_ip}:{dst_port}"
            + (f" ({sni_or_host})" if sni_or_host else "")
            + f" every {mean_int:.2f}s (Jitter: {jitter_pct:.1f}%, CV: {cv_ratio:.3f}, "
            f"Score: {periodicity_score}/100). Profile matches {framework_label}."
        )

        findings.append(
            BeaconFinding(
                flow_id=f"{src_ip}->{dst_ip}:{dst_port}/{app_proto}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=app_proto,
                packet_count=len(flow_pkts),
                total_bytes=total_bytes,
                first_seen=first_seen,
                last_seen=last_seen,
                duration_seconds=duration,
                mean_interval=round(mean_int, 2),
                median_interval=round(median_int, 2),
                std_dev=round(std_dev, 3),
                mad_interval=round(mad_int, 3),
                jitter_percent=round(jitter_pct, 1),
                cv_ratio=round(cv_ratio, 3),
                periodicity_score=periodicity_score,
                severity=severity,
                suspected_framework=framework_label,
                intervals=intervals[:40],
                sni_or_host=sni_or_host,
                ja3_hash=ja3_hash,
                mitre_technique_id=mitre_id,
                mitre_tactic="Command and Control",
                description=desc,
            )
        )

    findings.sort(key=lambda x: x.periodicity_score, reverse=True)
    return findings
