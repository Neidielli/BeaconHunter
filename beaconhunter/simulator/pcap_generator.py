"""
Synthetic PCAP Traffic Generator for Threat Hunting Demonstrations & Testing.
Uses Scapy (wrpcap) to craft a realistic multi-vector forensic packet capture containing:
  1. Benign Enterprise Traffic (Normal DNS, HTTPS handshakes to CDNs, HTTP requests)
  2. Cobalt Strike HTTPS C2 Beaconing (192.168.1.45 -> 185.220.101.34:443, ~60s interval, ~11% jitter, JA3/JA3S)
  3. Sliver C2 Implant mTLS Beaconing (192.168.1.45 -> 45.77.120.88:8443, ~15s interval, ~8% jitter, Go-TLS JA3)
  4. DNS Tunneling / Base64 & Hex Data Exfiltration (192.168.1.45 -> 8.8.8.8:53 via *.exfil.c2-shadow-ops.net)
  5. DGA (Domain Generation Algorithm) Burst & NXDOMAIN Spike (192.168.1.112 -> 8.8.8.8:53)
"""

import base64
import logging
import os
import random
import struct
from pathlib import Path
from typing import List, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap  # type: ignore


def build_tls_client_hello(
    tls_version: int,
    ciphers: List[int],
    extensions: List[int],
    elliptic_curves: List[int],
    ec_point_formats: List[int],
    sni: Optional[str] = None,
) -> bytes:
    """
    Constructs a binary RFC-compliant TLS Handshake ClientHello record (0x16, 0x01)
    whose dissected fields produce the exact specified JA3 fingerprint.
    """
    random_bytes = os.urandom(32)
    session_id = os.urandom(16)
    session_part = struct.pack("!B", len(session_id)) + session_id

    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_part = struct.pack("!H", len(cipher_bytes)) + cipher_bytes

    comp_part = b"\x01\x00"  # 1 compression method: null (0x00)

    ext_blocks = b""
    for ext_type in extensions:
        if ext_type == 0x0000 and sni:
            sni_bytes = sni.encode("utf-8")
            # ServerNameList length (2B) + NameType host_name (1B=0) + HostName length (2B) + HostName
            sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
            ext_data = struct.pack("!H", len(sni_entry)) + sni_entry
        elif ext_type == 0x000A:
            # Supported Groups / Elliptic Curves
            curves_raw = b"".join(struct.pack("!H", g) for g in elliptic_curves)
            ext_data = struct.pack("!H", len(curves_raw)) + curves_raw
        elif ext_type == 0x000B:
            # EC Point Formats
            fmt_raw = b"".join(struct.pack("!B", f) for f in ec_point_formats)
            ext_data = struct.pack("!B", len(fmt_raw)) + fmt_raw
        else:
            ext_data = b"\x00\x02\x00\x00"

        ext_blocks += struct.pack("!HH", ext_type, len(ext_data)) + ext_data

    ext_part = struct.pack("!H", len(ext_blocks)) + ext_blocks

    ch_body = (
        struct.pack("!H", tls_version)
        + random_bytes
        + session_part
        + cipher_part
        + comp_part
        + ext_part
    )

    # Handshake header: Type 1 (ClientHello) + 3-byte length
    hs_len_bytes = struct.pack("!I", len(ch_body))[1:]
    hs_record = b"\x01" + hs_len_bytes + ch_body

    # TLS Record Layer: ContentType 22 (Handshake) + Version 0x0301 + 2-byte length
    tls_record = b"\x16\x03\x01" + struct.pack("!H", len(hs_record)) + hs_record
    return tls_record


def build_tls_server_hello(
    tls_version: int,
    cipher: int,
    extensions: List[int],
) -> bytes:
    """
    Constructs a binary RFC-compliant TLS Handshake ServerHello record (0x16, 0x02)
    whose dissected fields produce the exact specified JA3S fingerprint.
    """
    random_bytes = os.urandom(32)
    session_id = os.urandom(16)
    session_part = struct.pack("!B", len(session_id)) + session_id
    cipher_part = struct.pack("!H", cipher)
    comp_part = b"\x00"

    ext_blocks = b""
    for ext_type in extensions:
        ext_data = b"\x00\x00"
        ext_blocks += struct.pack("!HH", ext_type, len(ext_data)) + ext_data

    ext_part = struct.pack("!H", len(ext_blocks)) + ext_blocks
    sh_body = (
        struct.pack("!H", tls_version)
        + random_bytes
        + session_part
        + cipher_part
        + comp_part
        + ext_part
    )

    hs_len_bytes = struct.pack("!I", len(sh_body))[1:]
    hs_record = b"\x02" + hs_len_bytes + sh_body
    tls_record = b"\x16\x03\x03" + struct.pack("!H", len(hs_record)) + hs_record
    return tls_record


def generate_synthetic_pcap(output_path: Path, seed: int = 42) -> Path:
    """
    Generates a comprehensive forensic PCAP file containing realistic C2 Beaconing,
    DNS Tunneling / Data Exfiltration, DGA Spikes, Malicious TLS JA3/JA3S, and Benign background traffic.
    """
    rng = random.Random(seed)
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packets = []
    base_time = 1763110000.0  # Fixed baseline epoch for reproducible forensic timelines

    def eth() -> Ether:
        return Ether(src="00:15:5d:01:02:03", dst="00:15:5d:01:02:01")

    def add_pkt(pkt, ts: float) -> None:
        pkt.time = ts
        packets.append(pkt)

    # -------------------------------------------------------------------------
    # 1. Cobalt Strike HTTPS C2 Beaconing
    #    192.168.1.45 -> 185.220.101.34:443 (Interval ~60s, Jitter ~11%)
    # -------------------------------------------------------------------------
    cs_client_hello = build_tls_client_hello(
        tls_version=771,
        ciphers=[49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        extensions=[0, 11, 10, 35, 16, 22, 23, 13],
        elliptic_curves=[29, 23, 24],
        ec_point_formats=[0],
        sni="cdn-Telemetry-update.azureedge-sync.com",
    )
    cs_server_hello = build_tls_server_hello(
        tls_version=771,
        cipher=49200,
        extensions=[65281, 11],
    )

    curr_t = base_time + 5.0
    for i in range(18):
        sport = 51000 + i
        # TCP SYN -> SYN-ACK -> ClientHello -> ServerHello -> Encrypted C2 Heartbeat
        syn = eth() / IP(src="192.168.1.45", dst="185.220.101.34") / TCP(sport=sport, dport=443, flags="S", seq=1000)
        ch = eth() / IP(src="192.168.1.45", dst="185.220.101.34") / TCP(sport=sport, dport=443, flags="PA", seq=1001) / Raw(load=cs_client_hello)
        sh = eth() / IP(src="185.220.101.34", dst="192.168.1.45") / TCP(sport=443, dport=sport, flags="PA", seq=2000) / Raw(load=cs_server_hello)

        add_pkt(syn, curr_t)
        add_pkt(ch, curr_t + 0.04)
        add_pkt(sh, curr_t + 0.09)

        # Sleep 60s with ~10-12% jitter
        jitter_offset = rng.uniform(-6.8, 6.8)
        curr_t += 60.0 + jitter_offset

    # -------------------------------------------------------------------------
    # 2. Sliver C2 Implant mTLS Beaconing on Non-Standard Port 8443
    #    192.168.1.45 -> 45.77.120.88:8443 (Interval ~15s, Jitter ~8%)
    # -------------------------------------------------------------------------
    sliver_client_hello = build_tls_client_hello(
        tls_version=771,
        ciphers=[49195, 49199, 49196, 49200, 52393, 52392, 49161, 49171, 49162, 49172],
        extensions=[0, 5, 10, 11, 13, 18, 16, 43, 51],
        elliptic_curves=[29, 23, 24, 25],
        ec_point_formats=[0],
        sni="mtls-gw.sliver-ops.org",
    )
    sliver_server_hello = build_tls_server_hello(
        tls_version=771,
        cipher=49199,
        extensions=[65281, 16],
    )

    curr_t = base_time + 12.0
    for i in range(24):
        sport = 52500 + i
        ch = (
            eth()
            / IP(src="192.168.1.45", dst="45.77.120.88")
            / TCP(sport=sport, dport=8443, flags="PA", seq=5000)
            / Raw(load=sliver_client_hello)
        )
        sh = (
            eth()
            / IP(src="45.77.120.88", dst="192.168.1.45")
            / TCP(sport=8443, dport=sport, flags="PA", seq=6000)
            / Raw(load=sliver_server_hello)
        )
        add_pkt(ch, curr_t)
        add_pkt(sh, curr_t + 0.05)

        jitter_offset = rng.uniform(-1.3, 1.3)
        curr_t += 15.0 + jitter_offset

    # -------------------------------------------------------------------------
    # 3. DNS Tunneling & Base64 / Hex Secret Exfiltration
    #    192.168.1.45 -> 8.8.8.8:53 (*.exfil.c2-shadow-ops.net)
    # -------------------------------------------------------------------------
    exfil_secrets = [
        b"CONFIDENTIAL_DB_DUMP:admin:P@ssw0rd2026!#99182",
        b"AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        b"SSH_PRIVATE_KEY_HEADER:MIIEpAIBAAKCAQEA0vx7agoebGcQSuu",
        b"INTERNAL_HOSTS:192.168.1.10_DC01_DOMAIN_ADMIN_HASH_NTLM",
        b"FINANCE_WIRE_TRANSFER_AUTH_TOKEN_88492019482019482019",
        b"CREDIT_CARD_VAULT_EXPORT_CHUNK_06_9928172635441239871",
        b"KERBEROS_TGT_TICKET_KRBTGT_CONTOSO_CORP_9918273645182",
        b"VPN_GATEWAY_CONFIG_IPSEC_PSK_S3cr3tTunnelKey#2026!!",
        b"SQL_PRODUCTION_CONNECTION_STRING_SA_MASTER_PASSWORD_99",
        b"SHADOW_COPY_SAM_SYSTEM_SECURITY_HIVE_DUMP_COMPLETED_OK",
    ]

    dns_t = base_time + 30.0
    for idx, secret_chunk in enumerate(exfil_secrets):
        b64_label = base64.urlsafe_b64encode(secret_chunk).decode("ascii").rstrip("=")
        # Split into two DNS labels if > 42 chars
        if len(b64_label) > 38:
            sub_q = f"{b64_label[:38]}.{b64_label[38:]}.exfil.c2-shadow-ops.net"
        else:
            sub_q = f"{b64_label}.exfil.c2-shadow-ops.net"

        dns_req = (
            eth()
            / IP(src="192.168.1.45", dst="8.8.8.8")
            / UDP(sport=54000 + idx, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=sub_q, qtype="TXT"))
        )
        dns_resp = (
            eth()
            / IP(src="8.8.8.8", dst="192.168.1.45")
            / UDP(sport=53, dport=54000 + idx)
            / DNS(
                id=idx + 1,
                qr=1,
                aa=1,
                rcode=0,
                qd=DNSQR(qname=sub_q, qtype="TXT"),
                an=DNSRR(rrname=sub_q, type="TXT", rdata="ACK_CHUNK_OK"),
            )
        )
        add_pkt(dns_req, dns_t)
        add_pkt(dns_resp, dns_t + 0.03)
        dns_t += rng.uniform(1.8, 3.5)

    # -------------------------------------------------------------------------
    # 4. DGA (Domain Generation Algorithm) Burst & NXDOMAIN Spike
    #    192.168.1.112 -> 8.8.8.8:53 (28 algorithmic domains in rapid succession)
    # -------------------------------------------------------------------------
    dga_domains = [
        "xkq9v2m8zpl1w.ru", "qzp7n4k9vb2x.biz", "m8v3k1p9zqw4.top",
        "zpl9x2v7k4m1n.xyz", "vbn8q2w9x4k7m.ru", "kjq4m9z2x8v1p.info",
        "wzx7k3v9m2p4q.cn", "pql8v2x9k4z7m.top", "nxz9k4m2v7q1w.ru",
        "bvx8z3k9m1q4p.biz", "tqw9x4v2k8z1m.xyz", "rjm7v3x9k2z8q.top",
        "fkp9z2x8v4m1q.ru", "gzq8k4v2x9m7p.info", "hvx9m3k7z2q1w.cn",
        "jpl7x9k2v4z8m.ru", "kmn8z4x2v9q7p.biz", "lqw9v3k8x2z1m.top",
        "mzx7k9v4q2p8w.xyz", "nvb8x2k9z4m7q.ru", "pqr9z3v8k2x1m.info",
        "qwx8k4v9z2m7p.top", "rvz9x2k7m4q8w.ru", "skp7v9x3z2m8q.biz",
    ]
    dga_t = base_time + 120.0
    for idx, dga_dom in enumerate(dga_domains):
        q_pkt = (
            eth()
            / IP(src="192.168.1.112", dst="8.8.8.8")
            / UDP(sport=55000 + idx, dport=53)
            / DNS(id=900 + idx, rd=1, qd=DNSQR(qname=dga_dom, qtype="A"))
        )
        # 90% return NXDOMAIN (rcode=3), last one resolves to active C2 IP 91.219.236.174
        is_nx = idx < (len(dga_domains) - 2)
        if is_nx:
            r_pkt = (
                eth()
                / IP(src="8.8.8.8", dst="192.168.1.112")
                / UDP(sport=53, dport=55000 + idx)
                / DNS(id=900 + idx, qr=1, rcode=3, qd=DNSQR(qname=dga_dom, qtype="A"))
            )
        else:
            r_pkt = (
                eth()
                / IP(src="8.8.8.8", dst="192.168.1.112")
                / UDP(sport=53, dport=55000 + idx)
                / DNS(
                    id=900 + idx,
                    qr=1,
                    rcode=0,
                    qd=DNSQR(qname=dga_dom, qtype="A"),
                    an=DNSRR(rrname=dga_dom, type="A", rdata="91.219.236.174"),
                )
            )
        add_pkt(q_pkt, dga_t)
        add_pkt(r_pkt, dga_t + 0.02)
        dga_t += rng.uniform(0.35, 0.95)

    # -------------------------------------------------------------------------
    # 5. Benign Enterprise Background Traffic (Browsing, Normal DNS, Standard TLS)
    # -------------------------------------------------------------------------
    benign_domains = [
        ("www.google.com", "142.250.190.36"),
        ("api.github.com", "140.82.121.6"),
        ("login.microsoftonline.com", "20.190.159.4"),
        ("cdnjs.cloudflare.com", "104.16.18.94"),
    ]
    benign_ch = build_tls_client_hello(
        tls_version=771,
        ciphers=[4865, 4866, 4867, 49195, 49199, 49196, 49200],
        extensions=[0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43],
        elliptic_curves=[29, 23, 24],
        ec_point_formats=[0],
        sni="www.google.com",
    )

    bg_t = base_time + 2.0
    for idx, (b_dom, b_ip) in enumerate(benign_domains):
        q = (
            eth()
            / IP(src="192.168.1.20", dst="8.8.8.8")
            / UDP(sport=56000 + idx, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=b_dom, qtype="A"))
        )
        r = (
            eth()
            / IP(src="8.8.8.8", dst="192.168.1.20")
            / UDP(sport=53, dport=56000 + idx)
            / DNS(
                qr=1,
                rcode=0,
                qd=DNSQR(qname=b_dom, qtype="A"),
                an=DNSRR(rrname=b_dom, type="A", rdata=b_ip),
            )
        )
        tls_p = (
            eth()
            / IP(src="192.168.1.20", dst=b_ip)
            / TCP(sport=56100 + idx, dport=443, flags="PA")
            / Raw(load=benign_ch)
        )
        add_pkt(q, bg_t)
        add_pkt(r, bg_t + 0.02)
        add_pkt(tls_p, bg_t + 0.15)
        bg_t += rng.uniform(18.0, 95.0)

    # Sort all packets chronologically and write PCAP
    packets.sort(key=lambda pkt: float(pkt.time))
    wrpcap(str(output_path), packets)
    return output_path
