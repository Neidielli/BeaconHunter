"""
Scapy-Powered PCAP/PCAPNG Packet Dissector & Byte-Level TLS Handshake Parser.
Extracts L3/L4 headers, DNS Queries/Answers, HTTP headers, and raw TLS ClientHello/ServerHello
fields required for Salesforce JA3 & JA3S fingerprinting without external Wireshark/tshark dependencies.
"""

import hashlib
import logging
import struct
from pathlib import Path
from typing import List, Dict, Tuple, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw  # type: ignore
from beaconhunter.models import PacketRecord


# RFC 8701 GREASE (Generate Random Extensions And Sustain Extensibility) values
# Must be ignored when computing JA3 / JA3S strings per Salesforce specification.
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

DNS_QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def compute_file_sha256(filepath: Path) -> str:
    """Computes cryptographic SHA-256 hash of the PCAP evidence file for chain of custody."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def parse_tls_handshake(payload: bytes) -> Optional[Dict]:
    """
    Parses raw TCP payload for a TLS Handshake record (ContentType 0x16).
    Extracts ClientHello (0x01) or ServerHello (0x02) fields for JA3/JA3S calculation:
      - TLS Version
      - Cipher Suites (filtered for GREASE)
      - Extensions (filtered for GREASE)
      - Elliptic Curves / Supported Groups (Extension 0x000a)
      - EC Point Formats (Extension 0x000b)
      - Server Name Indication / SNI (Extension 0x0000)
    """
    if len(payload) < 9:
        return None

    # Content Type 22 (0x16) = Handshake
    content_type = payload[0]
    if content_type != 0x16:
        return None

    record_version = struct.unpack("!H", payload[1:3])[0]
    if record_version not in (0x0300, 0x0301, 0x0302, 0x0303, 0x0304):
        return None

    record_len = struct.unpack("!H", payload[3:5])[0]
    hs_data = payload[5 : 5 + record_len]
    if len(hs_data) < 4:
        return None

    hs_type = hs_data[0]
    # 1 = ClientHello, 2 = ServerHello
    if hs_type not in (1, 2):
        return None

    hs_len = struct.unpack("!I", b"\x00" + hs_data[1:4])[0]
    body = hs_data[4 : 4 + hs_len]
    if len(body) < 34:
        return None

    tls_version = struct.unpack("!H", body[0:2])[0]
    # Skip 32-byte Random
    idx = 34

    if len(body) < idx + 1:
        return None
    session_id_len = body[idx]
    idx += 1 + session_id_len

    ciphers: List[int] = []
    extensions: List[int] = []
    elliptic_curves: List[int] = []
    ec_point_formats: List[int] = []
    sni: Optional[str] = None

    if hs_type == 1:
        # ClientHello
        if len(body) < idx + 2:
            return None
        cipher_suites_len = struct.unpack("!H", body[idx : idx + 2])[0]
        idx += 2
        if len(body) < idx + cipher_suites_len:
            return None
        for c_pos in range(idx, idx + cipher_suites_len, 2):
            if c_pos + 2 <= len(body):
                val = struct.unpack("!H", body[c_pos : c_pos + 2])[0]
                if val not in GREASE_VALUES:
                    ciphers.append(val)
        idx += cipher_suites_len

        # Compression methods
        if len(body) < idx + 1:
            return None
        comp_len = body[idx]
        idx += 1 + comp_len

    else:
        # ServerHello (hs_type == 2)
        if len(body) < idx + 3:
            return None
        cipher_val = struct.unpack("!H", body[idx : idx + 2])[0]
        if cipher_val not in GREASE_VALUES:
            ciphers.append(cipher_val)
        # +2 cipher, +1 compression method
        idx += 3

    # Parse Extensions if present
    if len(body) >= idx + 2:
        ext_total_len = struct.unpack("!H", body[idx : idx + 2])[0]
        idx += 2
        ext_end = min(len(body), idx + ext_total_len)

        while idx + 4 <= ext_end:
            ext_type = struct.unpack("!H", body[idx : idx + 2])[0]
            ext_len = struct.unpack("!H", body[idx + 2 : idx + 4])[0]
            idx += 4
            ext_data = body[idx : idx + ext_len]
            idx += ext_len

            if ext_type in GREASE_VALUES:
                continue

            extensions.append(ext_type)

            # Extension 0x0000: Server Name Indication (SNI)
            if ext_type == 0x0000 and len(ext_data) >= 5:
                sni_list_len = struct.unpack("!H", ext_data[0:2])[0]
                if sni_list_len >= 3 and ext_data[2] == 0:
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        sni = ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")

            # Extension 0x000a (10): Supported Groups / Elliptic Curves
            elif ext_type == 0x000A and len(ext_data) >= 2:
                curves_len = struct.unpack("!H", ext_data[0:2])[0]
                for g_pos in range(2, min(len(ext_data), 2 + curves_len), 2):
                    if g_pos + 2 <= len(ext_data):
                        curve = struct.unpack("!H", ext_data[g_pos : g_pos + 2])[0]
                        if curve not in GREASE_VALUES:
                            elliptic_curves.append(curve)

            # Extension 0x000b (11): EC Point Formats
            elif ext_type == 0x000B and len(ext_data) >= 1:
                fmt_len = ext_data[0]
                for f_pos in range(1, min(len(ext_data), 1 + fmt_len)):
                    ec_point_formats.append(ext_data[f_pos])

    return {
        "record_type": "ClientHello" if hs_type == 1 else "ServerHello",
        "tls_version": tls_version,
        "ciphers": ciphers,
        "extensions": extensions,
        "elliptic_curves": elliptic_curves,
        "ec_point_formats": ec_point_formats,
        "sni": sni,
    }


def parse_http_headers(payload: bytes) -> Optional[Dict[str, str]]:
    """Extracts basic HTTP Request metadata (Host, URI, User-Agent) if present."""
    try:
        if not payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"OPTIONS ")):
            return None
        header_block = payload.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="ignore")
        lines = header_block.split("\r\n")
        if not lines:
            return None
        parts = lines[0].split(" ")
        uri = parts[1] if len(parts) > 1 else "/"
        host = ""
        ua = ""
        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif lower.startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
        return {"uri": uri, "host": host, "user_agent": ua}
    except Exception:
        return None


def load_and_dissect_pcap(pcap_path: Path) -> Tuple[List[PacketRecord], Dict[str, int]]:
    """
    Reads a PCAP/PCAPNG file via Scapy and returns normalized PacketRecord objects
    along with protocol distribution statistics.
    """
    raw_packets = rdpcap(str(pcap_path))
    records: List[PacketRecord] = []
    proto_counts: Dict[str, int] = {
        "TCP": 0,
        "UDP": 0,
        "DNS": 0,
        "TLS": 0,
        "HTTP": 0,
        "OTHER": 0,
    }

    for idx, pkt in enumerate(raw_packets, start=1):
        ts = float(pkt.time)
        pkt_len = len(pkt)

        src_ip = ""
        dst_ip = ""
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            proto_counts["OTHER"] += 1
            continue

        src_port = 0
        dst_port = 0
        proto = "OTHER"
        tcp_flags = ""
        payload_bytes = b""

        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            proto = "TCP"
            tcp_flags = str(pkt[TCP].flags)
            proto_counts["TCP"] += 1
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            proto = "UDP"
            proto_counts["UDP"] += 1
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
        else:
            proto_counts["OTHER"] += 1

        record = PacketRecord(
            frame_number=idx,
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            length=pkt_len,
            tcp_flags=tcp_flags,
            payload_size=len(payload_bytes),
        )

        # Check DNS Layer
        if DNS in pkt:
            record.protocol = "DNS"
            proto_counts["DNS"] += 1
            dns_layer = pkt[DNS]
            record.dns_rcode = int(dns_layer.rcode)
            qd_obj = None
            if dns_layer.qd:
                if isinstance(dns_layer.qd, list) and len(dns_layer.qd) > 0:
                    qd_obj = dns_layer.qd[0]
                elif isinstance(dns_layer.qd, DNSQR) or hasattr(dns_layer.qd, "qname"):
                    qd_obj = dns_layer.qd

            if qd_obj is not None and hasattr(qd_obj, "qname"):
                qname = qd_obj.qname
                if isinstance(qname, bytes):
                    qname_str = qname.decode("utf-8", errors="ignore").rstrip(".")
                else:
                    qname_str = str(qname).rstrip(".")
                record.dns_query = qname_str
                qtype_int = int(getattr(qd_obj, "qtype", 1))
                record.dns_qtype = DNS_QTYPE_MAP.get(qtype_int, str(qtype_int))

            # Extract DNS answers if response
            if dns_layer.an:
                ans_list: List[str] = []
                an_items = dns_layer.an if isinstance(dns_layer.an, list) else [dns_layer.an]
                for item in an_items:
                    curr = item
                    while curr:
                        if hasattr(curr, "rdata"):
                            rdata = curr.rdata
                            if isinstance(rdata, bytes):
                                ans_list.append(rdata.decode("utf-8", errors="ignore"))
                            else:
                                ans_list.append(str(rdata))
                        curr = curr.payload if hasattr(curr, "payload") and curr.payload else None
                record.dns_answers = ans_list

        # Check TLS Handshake in TCP payload
        if payload_bytes and proto == "TCP":
            tls_info = parse_tls_handshake(payload_bytes)
            if tls_info:
                record.protocol = "TLS"
                proto_counts["TLS"] += 1
                record.tls_record_type = tls_info["record_type"]
                record.tls_version = tls_info["tls_version"]
                record.tls_ciphers = tls_info["ciphers"]
                record.tls_extensions = tls_info["extensions"]
                record.tls_elliptic_curves = tls_info["elliptic_curves"]
                record.tls_ec_point_formats = tls_info["ec_point_formats"]
                record.tls_sni = tls_info["sni"]
            else:
                http_info = parse_http_headers(payload_bytes)
                if http_info:
                    record.protocol = "HTTP"
                    proto_counts["HTTP"] += 1
                    record.http_host = http_info["host"]
                    record.http_uri = http_info["uri"]
                    record.http_user_agent = http_info["user_agent"]

        records.append(record)

    return records, proto_counts
