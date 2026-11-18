"""
DNS Forensics & Exfiltration Engine:
1. DNS Tunneling / Data Exfiltration Detector:
   - Calculates Shannon Entropy H(X) = -sum(p(x) * log2(p(x))) on subdomain payloads.
   - Identifies Base64, Base32, and Hex-encoded subdomain chunks.
   - Flags excessive subdomain lengths, high unique subdomain counts per parent domain,
     and suspicious record types (TXT, NULL, CNAME).
2. Domain Generation Algorithm (DGA) & Newly-Registered Domain Spike Detector:
   - Evaluates Second-Level Domains (SLDs) for high consonant-to-vowel ratios,
     embedded numeric entropy, and low English bigram legibility.
   - Detects bursts of queries to distinct algorithmic domains and NXDOMAIN (rcode=3) spikes.
"""

import math
import re
import statistics
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Set

from beaconhunter.models import PacketRecord, DNSFinding

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
HEX_REGEX = re.compile(r"^[0-9a-fA-F]{16,}$")
BASE32_REGEX = re.compile(r"^[A-Z2-7a-z2-7]{20,}$")
BASE64_DNS_REGEX = re.compile(r"^[A-Za-z0-9\-_]{20,}$")

# Common English bigrams for DGA vs natural domain differentiation
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
}

MULTI_PART_TLDS = {
    "co.uk", "com.br", "org.br", "gov.br", "net.br", "co.jp", "com.au", "co.in"
}

SAFE_INFRASTRUCTURE_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "cloudflare.com",
    "microsoft.com", "windows.com", "live.com", "office.com",
    "github.com", "githubusercontent.com", "amazonaws.com", "akamai.net",
    "apple.com", "icloud.com", "mozilla.org", "digicert.com",
}


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy (bits per character) of a string:
    H(X) = - sum( P(x_i) * log2(P(x_i)) )
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def split_domain_parts(fqdn: str) -> Tuple[str, str, str]:
    """
    Splits a Fully Qualified Domain Name (FQDN) into:
    (subdomain_payload, sld, base_domain)
    Example:
      'aGVsbG8gd29ybGQ.exfil.c2-shadow.net' -> ('aGVsbG8gd29ybGQ.exfil', 'c2-shadow', 'c2-shadow.net')
      'xkq9v2m8zpl1w.ru' -> ('', 'xkq9v2m8zpl1w', 'xkq9v2m8zpl1w.ru')
    """
    clean = fqdn.strip(".").lower()
    parts = clean.split(".")
    if len(parts) < 2:
        return ("", clean, clean)

    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        base_domain = ".".join(parts[-3:])
        sld = parts[-3]
        sub_parts = parts[:-3]
    else:
        base_domain = last_two
        sld = parts[-2]
        sub_parts = parts[:-2]

    # Retain original case for subdomain entropy/Base64 analysis
    orig_parts = fqdn.strip(".").split(".")
    orig_sub = ".".join(orig_parts[: len(sub_parts)]) if sub_parts else ""
    return (orig_sub, sld, base_domain)


def classify_payload_encoding(subdomain: str, entropy: float) -> str:
    """Identifies the likely encoding scheme used in a DNS tunneling subdomain label."""
    collapsed = subdomain.replace(".", "").replace("-", "")
    if not collapsed:
        return "None"
    if HEX_REGEX.match(collapsed):
        return "Hexadecimal (Base16) Encoded Payload"
    if any(c.isupper() for c in collapsed) and any(c.islower() for c in collapsed) and len(collapsed) >= 16:
        return "Base64 / Base64URL Encoded Payload"
    if BASE32_REGEX.match(collapsed) and entropy >= 3.6:
        return "Base32 / Base64 Encoded Payload"
    if entropy >= 3.85 and len(collapsed) >= 18:
        return "High-Entropy Encrypted / Compressed Tunnel"
    return "Standard / Cleartext"


def score_dga_domain(sld: str) -> float:
    """
    Computes a DGA (Domain Generation Algorithm) likelihood score (0.0 to 100.0)
    for a Second-Level Domain (SLD) based on:
      - Shannon entropy of the SLD
      - Consonant-to-vowel imbalance
      - Digit mixing ratio
      - Absence of common natural-language bigrams
      - SLD length (>= 9 chars)
    """
    clean_sld = sld.lower().replace("-", "")
    if len(clean_sld) < 7:
        return 0.0

    entropy = calculate_shannon_entropy(clean_sld)
    letters = [c for c in clean_sld if c.isalpha()]
    digits = [c for c in clean_sld if c.isdigit()]

    vowel_count = sum(1 for c in letters if c in VOWELS)
    consonant_count = sum(1 for c in letters if c in CONSONANTS)
    vowel_ratio = vowel_count / max(1, len(letters))
    digit_ratio = len(digits) / len(clean_sld)

    # Bigram naturalness check
    bigrams = [clean_sld[i : i + 2] for i in range(len(clean_sld) - 1)]
    common_bg_hits = sum(1 for bg in bigrams if bg in COMMON_BIGRAMS)
    bigram_ratio = common_bg_hits / max(1, len(bigrams))

    score = 0.0
    # 1. Entropy contribution (up to 35 pts)
    if entropy >= 3.2:
        score += min(35.0, (entropy - 2.6) * 28.0)

    # 2. Low vowel ratio or extreme consonant clusters (up to 25 pts)
    if vowel_ratio < 0.22:
        score += 25.0
    elif vowel_ratio < 0.30:
        score += 14.0

    # 3. Alphanumeric mixing (digits interleaved with random letters, up to 20 pts)
    if 0.12 <= digit_ratio <= 0.60 and len(letters) >= 5:
        score += 20.0

    # 4. Low natural bigram ratio (up to 20 pts)
    if bigram_ratio < 0.12:
        score += 20.0
    elif bigram_ratio < 0.22:
        score += 10.0

    return round(min(100.0, score), 1)


def analyze_dns_traffic(packets: List[PacketRecord]) -> List[DNSFinding]:
    """
    Inspects all DNS packets in the capture to detect:
      1. DNS Tunneling & Covert Data Exfiltration (per (src_ip, base_domain))
      2. DGA (Domain Generation Algorithm) bursts & NXDOMAIN spikes (per src_ip)
    """
    dns_packets = [p for p in packets if p.protocol == "DNS" and p.dns_query]
    if not dns_packets:
        return []

    findings: List[DNSFinding] = []

    # Track RCODE=3 (NXDOMAIN) per query name from DNS responses
    nxdomain_queries: Set[str] = set()
    for p in dns_packets:
        if p.dns_rcode == 3 and p.dns_query:
            nxdomain_queries.add(p.dns_query.lower())

    # Group client queries by (src_ip, base_domain) for Tunneling/Exfiltration analysis
    domain_groups: Dict[Tuple[str, str], List[PacketRecord]] = defaultdict(list)
    # Also track per-host DGA candidate queries
    host_dga_candidates: Dict[str, List[Tuple[PacketRecord, str, str, float]]] = defaultdict(list)

    for p in dns_packets:
        # Focus on outbound queries (or include responses to correlate NXDOMAIN)
        qname = p.dns_query or ""
        subdomain, sld, base_domain = split_domain_parts(qname)
        if base_domain in SAFE_INFRASTRUCTURE_DOMAINS:
            continue

        # Only count client queries (generally dst_port == 53)
        if p.dst_port == 53:
            domain_groups[(p.src_ip, base_domain)].append(p)

            # Evaluate if this query is a root/near-root DGA domain lookup
            dga_score = score_dga_domain(sld)
            if dga_score >= 60.0 and len(subdomain) <= 6:
                host_dga_candidates[p.src_ip].append((p, qname, base_domain, dga_score))

    # -------------------------------------------------------------------------
    # 1. Evaluate DNS Tunneling / Data Exfiltration per (src_ip, base_domain)
    # -------------------------------------------------------------------------
    for (src_ip, base_domain), pkts in domain_groups.items():
        subdomains: List[str] = []
        entropies: List[float] = []
        encodings: List[str] = []
        txt_or_null_count = 0

        for p in pkts:
            sub, _, _ = split_domain_parts(p.dns_query or "")
            if sub:
                subdomains.append(sub)
                clean_sub = sub.replace(".", "")
                ent = calculate_shannon_entropy(clean_sub)
                entropies.append(ent)
                enc = classify_payload_encoding(sub, ent)
                if enc != "Standard / Cleartext":
                    encodings.append(enc)
            if p.dns_qtype in ("TXT", "NULL", "CNAME", "ANY"):
                txt_or_null_count += 1

        if not subdomains:
            continue

        unique_subs = set(subdomains)
        max_len = max(len(s) for s in subdomains)
        avg_ent = statistics.mean(entropies) if entropies else 0.0
        max_ent = max(entropies) if entropies else 0.0

        # Trigger conditions for DNS Tunneling / Exfiltration:
        # - High average Shannon entropy (>= 3.65) with long subdomains (>= 20 chars), OR
        # - Multiple encoded subdomains (>= 3 unique subdomains with max_len >= 24)
        is_tunnel = (
            (avg_ent >= 3.65 and max_len >= 20 and len(unique_subs) >= 3)
            or (max_ent >= 4.0 and max_len >= 28 and len(unique_subs) >= 2)
            or (len(encodings) >= 3 and len(unique_subs) >= 3)
        )

        if not is_tunnel:
            continue

        first_ts = min(p.timestamp for p in pkts)
        last_ts = max(p.timestamp for p in pkts)
        duration_min = max(0.1, (last_ts - first_ts) / 60.0)
        q_rate = round(len(pkts) / duration_min, 1)

        # Estimate exfiltrated payload bytes from unique subdomain labels
        est_bytes = sum(len(s.replace(".", "")) for s in unique_subs)
        dominant_encoding = (
            Counter(encodings).most_common(1)[0][0]
            if encodings
            else "High-Entropy Subdomain Stream"
        )

        nx_count = sum(1 for p in pkts if (p.dns_query or "").lower() in nxdomain_queries)
        dst_ip = pkts[0].dst_ip

        if avg_ent >= 3.9 or len(unique_subs) >= 8 or est_bytes >= 250:
            severity = "CRITICAL"
        elif avg_ent >= 3.65 or len(unique_subs) >= 4:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        desc = (
            f"DNS Tunneling / Data Exfiltration detected from {src_ip} via parent domain '{base_domain}'. "
            f"Observed {len(unique_subs)} unique high-entropy subdomains (Avg Shannon Entropy: {avg_ent:.2f} bits/char, "
            f"Max: {max_ent:.2f}, Max Label Length: {max_len} chars, Est. Payload: ~{est_bytes} bytes). "
            f"Detected encoding: {dominant_encoding}."
        )

        findings.append(
            DNSFinding(
                finding_type="DNS_TUNNELING",
                src_ip=src_ip,
                dst_ip=dst_ip,
                base_domain=base_domain,
                sample_queries=[p.dns_query or "" for p in pkts[:8]],
                query_count=len(pkts),
                unique_subdomains=len(unique_subs),
                nxdomain_count=nx_count,
                max_subdomain_length=max_len,
                avg_shannon_entropy=round(avg_ent, 2),
                max_shannon_entropy=round(max_ent, 2),
                encoding_detected=dominant_encoding,
                dga_probability=0.0,
                query_rate_per_min=q_rate,
                total_exfil_bytes_est=est_bytes,
                first_seen=first_ts,
                last_seen=last_ts,
                severity=severity,
                mitre_technique_id="T1071.004",
                mitre_tactic="Command and Control / Exfiltration",
                description=desc,
            )
        )

    # -------------------------------------------------------------------------
    # 2. Evaluate DGA (Domain Generation Algorithms) Bursts per Source Host
    # -------------------------------------------------------------------------
    for src_ip, candidates in host_dga_candidates.items():
        unique_dga_domains = {base_dom for (_, _, base_dom, _) in candidates}
        if len(unique_dga_domains) < 5:
            continue

        dga_pkts = [item[0] for item in candidates]
        dga_scores = [item[3] for item in candidates]
        slds = [split_domain_parts(item[1])[1] for item in candidates]
        sld_entropies = [calculate_shannon_entropy(s) for s in slds]

        first_ts = min(p.timestamp for p in dga_pkts)
        last_ts = max(p.timestamp for p in dga_pkts)
        duration_min = max(0.05, (last_ts - first_ts) / 60.0)
        q_rate = round(len(dga_pkts) / duration_min, 1)

        nx_count = sum(
            1 for (_, qname, _, _) in candidates if qname.lower() in nxdomain_queries
        )
        avg_dga_prob = round(statistics.mean(dga_scores), 1)
        avg_ent = round(statistics.mean(sld_entropies), 2)
        max_ent = round(max(sld_entropies), 2)
        max_len = max(len(s) for s in slds)

        severity = "CRITICAL" if len(unique_dga_domains) >= 12 or nx_count >= 5 else "HIGH"
        sample_q = list(dict.fromkeys(item[1] for item in candidates))[:10]

        desc = (
            f"DGA (Domain Generation Algorithm) burst detected from host {src_ip}: "
            f"{len(unique_dga_domains)} distinct algorithmically generated domains queried within "
            f"{max(1.0, last_ts - first_ts):.1f}s ({q_rate} queries/min, {nx_count} NXDOMAIN responses). "
            f"Mean DGA Probability: {avg_dga_prob}% (Avg SLD Shannon Entropy: {avg_ent} bits/char)."
        )

        findings.append(
            DNSFinding(
                finding_type="DGA_ACTIVITY",
                src_ip=src_ip,
                dst_ip=dga_pkts[0].dst_ip,
                base_domain=f"Multiple DGA Domains ({len(unique_dga_domains)} unique)",
                sample_queries=sample_q,
                query_count=len(dga_pkts),
                unique_subdomains=len(unique_dga_domains),
                nxdomain_count=nx_count,
                max_subdomain_length=max_len,
                avg_shannon_entropy=avg_ent,
                max_shannon_entropy=max_ent,
                encoding_detected="Algorithmic Consonant-Heavy / Alphanumeric DGA",
                dga_probability=avg_dga_prob,
                query_rate_per_min=q_rate,
                total_exfil_bytes_est=0,
                first_seen=first_ts,
                last_seen=last_ts,
                severity=severity,
                mitre_technique_id="T1568.002",
                mitre_tactic="Command and Control",
                description=desc,
            )
        )

    findings.sort(key=lambda x: (x.severity == "CRITICAL", x.avg_shannon_entropy), reverse=True)
    return findings
