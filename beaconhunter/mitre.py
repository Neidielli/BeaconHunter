"""
MITRE ATT&CK v14 Mapping & JA3/JA3S Threat Intelligence Database.
Provides enrichment for C2 Beaconing, DNS Tunneling, DGA, and Malicious TLS Fingerprints.
"""

from typing import Dict, Any, Optional

MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1071.001": {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": "Adversaries communicate using HTTP/HTTPS application layer protocols with periodic heartbeats and jitter to blend in with normal web traffic.",
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
        "description": "Adversaries encapsulate C2 traffic or exfiltrate payloads within high-entropy DNS subdomain queries (DNS Tunneling).",
    },
    "T1568.002": {
        "id": "T1568.002",
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1568/002/",
        "description": "Malware algorithmically generates large bursts of pseudo-random domain names (DGA) to locate active C2 rendezvous nodes.",
    },
    "T1573.002": {
        "id": "T1573.002",
        "name": "Encrypted Channel: Asymmetric Cryptography (TLS/JA3)",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1573/002/",
        "description": "Adversaries employ TLS encryption for C2 transport whose underlying socket libraries produce distinctive JA3/JA3S fingerprints.",
    },
    "T1048.003": {
        "id": "T1048.003",
        "name": "Exfiltration Over Alternative Protocol: DNS Exfiltration",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1048/003/",
        "description": "Sensitive host data is encoded in Base64/Hex/Base32 chunks and transmitted outbound as DNS subdomain labels.",
    },
    "T1571": {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1571/",
        "description": "C2 channels operating over unusual TCP/UDP ports or mismatched protocol/port combinations (e.g., mTLS/HTTPS over 8443/4444).",
    },
}


# Curated Threat Intelligence Database of Known Malicious & Suspicious JA3 / JA3S Hashes
# Format: md5_hash -> {family, signature, severity, type, description}
JA3_THREAT_DB: Dict[str, Dict[str, Any]] = {
    # Cobalt Strike Client & Server JA3/JA3S Fingerprints
    "72a589da586844d7f0818ce684948eea": {
        "family": "Cobalt Strike",
        "signature": "Cobalt Strike Beacon (WinInet Default HTTPS Profile)",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Default Cobalt Strike HTTPS beacon TLS ClientHello fingerprint commonly observed in red team and APT operations.",
    },
    "a2183387e54b0d3da187bec0c5e27c7b": {
        "family": "Cobalt Strike",
        "signature": "Cobalt Strike 4.x Malleable C2 HTTPS Implant",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Cobalt Strike HTTPS beacon ClientHello masquerading as CDN telemetry over TLS 1.2.",
    },
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "family": "Cobalt Strike",
        "signature": "Cobalt Strike Beacon (WinHTTP / Malleable C2)",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Cobalt Strike Malleable C2 HTTPS client fingerprint using WinHTTP socket stack.",
    },
    "fd4bc6cea4877646ccd62f0792ec0b62": {
        "family": "Cobalt Strike",
        "signature": "Cobalt Strike TeamServer Default TLS (JA3S)",
        "severity": "CRITICAL",
        "type": "JA3S",
        "description": "ServerHello TLS fingerprint matching default Java/NanoHTTPD TLS stack used by Cobalt Strike TeamServer.",
    },
    "0debd3853f330c574b05e0b6d882dc27": {
        "family": "Cobalt Strike",
        "signature": "Cobalt Strike TeamServer Malleable C2 Listener (JA3S)",
        "severity": "CRITICAL",
        "type": "JA3S",
        "description": "Cobalt Strike TeamServer TLS 1.2 ServerHello response signature negotiated with HTTPS beacon implants.",
    },
    "ae4edc6faf64d08308082ad26be60767": {
        "family": "Cobalt Strike",
        "signature": "Cobalt Strike TeamServer TLSv1.2 (JA3S)",
        "severity": "CRITICAL",
        "type": "JA3S",
        "description": "Cobalt Strike TeamServer JA3S response signature negotiated with beacon implants.",
    },
    # Sliver C2 Framework
    "51c64c77e60f3980eea90869b68c58a8": {
        "family": "Sliver C2",
        "signature": "Sliver Implant Go-TLS Client (mTLS / HTTPS)",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Golang crypto/tls stack fingerprint characteristic of Sliver C2 implants and Mythic Poseidon/Medusa agents.",
    },
    "4a397452e1d6a3fcb72dec5842a1ca06": {
        "family": "Sliver C2",
        "signature": "Sliver C2 mTLS Implant (Golang crypto/tls Handshake)",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Sliver C2 implant mTLS ClientHello fingerprint over non-standard port 8443.",
    },
    "ec74a5c51106f0419184d0dd08fb05bc": {
        "family": "Sliver C2",
        "signature": "Sliver Server mTLS Listener (JA3S)",
        "severity": "HIGH",
        "type": "JA3S",
        "description": "Sliver C2 multiplayer server mTLS listener response fingerprint.",
    },
    "7bee5c1d424b7e5f943b06983bb11422": {
        "family": "Sliver C2",
        "signature": "Sliver C2 Server mTLS Listener Response (JA3S)",
        "severity": "HIGH",
        "type": "JA3S",
        "description": "Sliver C2 server mTLS ServerHello handshake negotiated on port 8443.",
    },
    # Mythic / Python C2 Agents
    "3b5074b1b5d032e5620f69f9f700ff0e": {
        "family": "Mythic C2",
        "signature": "Mythic C2 / Python urllib3 Headless Agent",
        "severity": "HIGH",
        "type": "JA3",
        "description": "Headless Python TLS client fingerprint associated with Mythic Medusa and custom Python C2 agents.",
    },
    # Metasploit Meterpreter
    "5d65ea3fb1d4aa7d826733d2f2cbbb1d": {
        "family": "Metasploit",
        "signature": "Metasploit Meterpreter Reverse HTTPS",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Metasploit stage/stager reverse_https TLS fingerprint.",
    },
    # AsyncRAT / QuasarRAT
    "6734f37431670b3ab4292b8f60f29984": {
        "family": "AsyncRAT",
        "signature": "AsyncRAT / .NET SslStream C2 Client",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Classic .NET SslStream handshake signature used by AsyncRAT, DcRat, and QuasarRAT.",
    },
    # TrickBot / Emotet
    "4d7a28d6f2263ed61de88ca66eb011e3": {
        "family": "Emotet / TrickBot",
        "signature": "Emotet Loader / TrickBot Banking Trojan",
        "severity": "CRITICAL",
        "type": "JA3",
        "description": "Known malicious TLS fingerprint linked to Emotet and TrickBot C2 communication.",
    },
    # Tor Client
    "e7d705a3286e19ea42f587b344ee6865": {
        "family": "Tor Network",
        "signature": "Tor Anonymizer TLS Client",
        "severity": "HIGH",
        "type": "JA3",
        "description": "Tor ORPort TLS handshake signature indicating darknet proxy or covert C2 routing.",
    },
}

# Benign Known Fingerprints for Reference (so analysts can distinguish standard browsers)
JA3_BENIGN_DB: Dict[str, str] = {
    "b32309a26951912be7dba376398abc3b": "Standard Chrome / Edge Chromium Browser",
    "773906b0efdefa24a7f2b8eb6985bf37": "Standard Mozilla Firefox Browser",
    "eb1d94daa7e0344597e756a1fb6e7054": "Standard TLS 1.2 Server Response (Cloudflare/Nginx)",
}


def lookup_ja3(ja3_hash: str) -> Optional[Dict[str, Any]]:
    """Checks if a JA3 or JA3S MD5 hash matches known threat intelligence signatures."""
    return JA3_THREAT_DB.get(ja3_hash.lower())


def get_mitre_info(technique_id: str) -> Dict[str, str]:
    """Returns MITRE ATT&CK metadata for a technique ID."""
    return MITRE_TECHNIQUES.get(
        technique_id,
        {
            "id": technique_id,
            "name": "Network Command and Control",
            "tactic": "Command and Control",
            "url": "https://attack.mitre.org/",
            "description": "Suspicious network command and control or exfiltration activity.",
        },
    )
