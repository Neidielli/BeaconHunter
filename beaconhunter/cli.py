"""
Rich & Typer Interactive Command-Line Interface for BeaconHunter.
Commands:
  - scan      : Dissect a PCAP/PCAPNG file, hunt for C2 Beaconing, DNS Tunneling/DGA, and TLS JA3/JA3S,
                display Rich terminal tables + topology tree, and export CSVs & HTML dashboard.
  - simulate  : Generate a synthetic APT intrusion PCAP (Cobalt Strike, Sliver, DNS Tunneling, DGA)
                and optionally run the full analysis pipeline immediately.
  - ja3-db    : Inspect the curated JA3 / JA3S Threat Intelligence Signature Database.
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich import box

from beaconhunter.analyzers.graph_builder import run_full_pcap_analysis
from beaconhunter.exporters.csv_exporter import export_forensic_csv_suite
from beaconhunter.exporters.html_dashboard import generate_html_dashboard
from beaconhunter.mitre import JA3_THREAT_DB, MITRE_TECHNIQUES
from beaconhunter.models import ForensicAnalysisReport
from beaconhunter.simulator.pcap_generator import generate_synthetic_pcap

app = typer.Typer(
    name="beaconhunter",
    help="BeaconHunter — PCAP Network Forensics & C2 Beaconing Threat Hunting Engine",
    add_completion=False,
)
console = Console()

BANNER = r"""[bold bright_green]
  ____                            _   _             _            
 | __ )  ___  __ _  ___ ___  _ __| | | |_   _ _ __ | |_ ___ _ __ 
 |  _ \ / _ \/ _` |/ __/ _ \| '_ \ |_| | | | | '_ \| __/ _ \ '__|
 | |_) |  __/ (_| | (_| (_) | | | |  _  | |_| | | | | ||  __/ |   
 |____/ \___|\__,_|\___\___/|_| |_|_| |_|\__,_|_| |_|\__\___|_|   
[/bold bright_green][bold cyan]  >> PCAP Network Forensics & C2 Beaconing Threat Hunting Engine v1.0.0[/bold cyan]
[dim]  >> Developed by Neidielli Rosado • MITRE ATT&CK v14 • ISO/IEC 27037[/dim]
"""


def _severity_badge(sev: str) -> str:
    if sev == "CRITICAL":
        return "[bold white on red] CRITICAL [/bold white on red]"
    if sev == "HIGH":
        return "[bold black on yellow] HIGH [/bold black on yellow]"
    if sev == "MEDIUM":
        return "[bold black on cyan] MEDIUM [/bold black on cyan]"
    return f"[dim]{sev}[/dim]"


def render_terminal_report(report: ForensicAnalysisReport) -> None:
    """Renders Rich tables, summary panels, and the network communication graph tree in the terminal."""
    console.print(BANNER)

    # 1. Overview Panel
    mal_ja3 = sum(1 for j in report.ja3_findings if j.is_malicious)
    summary_text = (
        f"[bold cyan]Evidence File:[/bold cyan] {report.pcap_path}\n"
        f"[bold cyan]SHA-256 Hash :[/bold cyan] {report.pcap_sha256}\n"
        f"[bold cyan]Capture Stats:[/bold cyan] {report.total_packets} packets | "
        f"Duration: {report.capture_duration_seconds}s | Size: {report.file_size_bytes:,} bytes\n"
        f"[bold cyan]Findings     :[/bold cyan] "
        f"[bold red]{len(report.alerts)} Total Alerts[/bold red] • "
        f"[bold magenta]{len(report.beacons)} C2 Beacons[/bold magenta] • "
        f"[bold yellow]{len(report.dns_findings)} DNS Anomalies[/bold yellow] • "
        f"[bold green]{mal_ja3} Malicious JA3/JA3S[/bold green]"
    )
    console.print(
        Panel(
            summary_text,
            title="[bold bright_green]⚖️ Forensic Evidence & Triage Summary[/bold bright_green]",
            border_style="bright_green",
        )
    )

    # 2. C2 Beaconing Table
    if report.beacons:
        b_table = Table(
            title="🎯 Statistical C2 Beaconing Detection (Jitter & Periodicity Analysis)",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold bright_cyan",
        )
        b_table.add_column("Severity", justify="center")
        b_table.add_column("Flow (Source -> Target)", style="bold white")
        b_table.add_column("Mean Sleep", justify="right", style="bright_green")
        b_table.add_column("Jitter %", justify="right", style="yellow")
        b_table.add_column("CV (σ/μ)", justify="right")
        b_table.add_column("Score", justify="right", style="bold magenta")
        b_table.add_column("Suspected C2 Profile & SNI")

        for b in report.beacons:
            sni_part = f" [dim]({b.sni_or_host})[/dim]" if b.sni_or_host else ""
            b_table.add_row(
                _severity_badge(b.severity),
                f"{b.src_ip} -> {b.dst_ip}:{b.dst_port}/{b.protocol}",
                f"{b.mean_interval:.2f}s",
                f"{b.jitter_percent:.1f}%",
                f"{b.cv_ratio:.3f}",
                f"{b.periodicity_score:.1f}/100",
                f"{b.suspected_framework}{sni_part}",
            )
        console.print(b_table)

    # 3. DNS Forensics Table (Tunneling & DGA)
    if report.dns_findings:
        d_table = Table(
            title="🧬 DNS Forensics: Shannon Entropy Tunneling & DGA Bursts",
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold yellow",
        )
        d_table.add_column("Severity", justify="center")
        d_table.add_column("Type", style="bold cyan")
        d_table.add_column("Source Host", style="white")
        d_table.add_column("Domain / Cluster", style="bold green")
        d_table.add_column("Queries (Uniq)", justify="right")
        d_table.add_column("NXDOMAIN", justify="right", style="red")
        d_table.add_column("Entropy (Avg/Max)", justify="right", style="bright_magenta")
        d_table.add_column("Detected Encoding / Pattern")

        for d in report.dns_findings:
            d_table.add_row(
                _severity_badge(d.severity),
                f"{d.finding_type}\n[dim]{d.mitre_technique_id}[/dim]",
                d.src_ip,
                d.base_domain,
                f"{d.query_count} ({d.unique_subdomains})",
                str(d.nxdomain_count),
                f"{d.avg_shannon_entropy:.2f} / {d.max_shannon_entropy:.2f} bits",
                d.encoding_detected,
            )
        console.print(d_table)

    # 4. TLS JA3 / JA3S Fingerprints Table
    if report.ja3_findings:
        j_table = Table(
            title="🔐 TLS/SSL JA3 & JA3S Cryptographic Fingerprinting",
            box=box.ROUNDED,
            border_style="magenta",
            header_style="bold bright_magenta",
        )
        j_table.add_column("Severity", justify="center")
        j_table.add_column("Type", style="bold")
        j_table.add_column("Session", style="white")
        j_table.add_column("SNI", style="cyan")
        j_table.add_column("JA3 / JA3S MD5 Hash", style="yellow")
        j_table.add_column("Family", style="bold bright_green")
        j_table.add_column("Matched Signature")

        for j in report.ja3_findings:
            j_table.add_row(
                _severity_badge(j.severity),
                j.fingerprint_type,
                f"{j.src_ip} -> {j.dst_ip}:{j.dst_port}",
                j.sni,
                j.ja3_hash,
                j.malware_family,
                j.matched_signature,
            )
        console.print(j_table)

    # 5. Suspicious Communication Topology Tree
    if report.graph_edges:
        topo_tree = Tree("🕸️ [bold bright_cyan]Suspicious Network Communication Graph (Nodes & C2 Channels)[/bold bright_cyan]")
        by_src = {}
        for e in report.graph_edges:
            by_src.setdefault(e.source, []).append(e)

        for src, edge_list in by_src.items():
            src_branch = topo_tree.add(f"[bold bright_green]Host {src}[/bold bright_green]")
            for e in edge_list:
                color = "red" if e.severity == "CRITICAL" else "yellow"
                src_branch.add(
                    f"[{color}]──({e.protocol}/{e.port}: {e.relationship})──>[/{color}] "
                    f"[bold white]{e.target}[/bold white] [dim]({e.packet_count} pkts, {e.byte_volume:,} bytes)[/dim]"
                )
        console.print(Panel(topo_tree, border_style="cyan"))


@app.command("scan")
def scan_command(
    input_pcap: Path = typer.Option(
        ..., "--input", "-i", help="Path to the input PCAP or PCAPNG file to analyze."
    ),
    output_dir: Path = typer.Option(
        Path("output"), "--output", "-o", help="Directory where CSVs, DOT graph, and HTML report will be saved."
    ),
) -> None:
    """
    Analyze a PCAP/PCAPNG capture for C2 Beaconing, DNS Tunneling, DGA, and Malicious TLS JA3/JA3S.
    """
    if not input_pcap.exists():
        console.print(f"[bold red][!] Error:[/bold red] PCAP file not found: {input_pcap}")
        raise typer.Exit(code=1)

    report = run_full_pcap_analysis(input_pcap)
    render_terminal_report(report)

    exported = export_forensic_csv_suite(report, output_dir)
    html_path = generate_html_dashboard(report, Path(output_dir) / "report.html")

    out_tree = Tree(f"📂 [bold bright_green]Exported Forensic Artifacts ({Path(output_dir).resolve()})[/bold bright_green]")
    for label, fpath in exported.items():
        out_tree.add(f"[cyan]{fpath.name}[/cyan] [dim]({label})[/dim]")
    out_tree.add(f"[bold bright_yellow]{html_path.name}[/bold bright_yellow] [dim](Interactive HTML5 Dashboard & Force Graph)[/dim]")
    console.print(out_tree)


@app.command("simulate")
def simulate_command(
    output_pcap: Path = typer.Option(
        Path("samples/c2_apt_intrusion.pcap"),
        "--pcap",
        "-p",
        help="Destination path for the generated synthetic PCAP file.",
    ),
    analyze: bool = typer.Option(
        True,
        "--analyze/--no-analyze",
        help="Automatically run the full forensic threat hunting analysis after generating the PCAP.",
    ),
    report_dir: Path = typer.Option(
        Path("output"),
        "--output",
        "-o",
        help="Output folder for forensic CSVs and HTML dashboard if --analyze is enabled.",
    ),
) -> None:
    """
    Generate a realistic synthetic PCAP containing Cobalt Strike & Sliver C2 Beaconing,
    DNS Base64 Exfiltration Tunneling, DGA spikes, and TLS JA3/JA3S handshakes.
    """
    generated_path = generate_synthetic_pcap(output_pcap)
    console.print(
        f"[bold bright_green][✓] Synthetic APT Intrusion PCAP generated at:[/bold bright_green] [cyan]{generated_path}[/cyan]"
    )
    if analyze:
        report = run_full_pcap_analysis(generated_path)
        render_terminal_report(report)
        exported = export_forensic_csv_suite(report, report_dir)
        html_path = generate_html_dashboard(report, Path(report_dir) / "report.html")
        console.print(
            f"\n[bold bright_green][✓] Full Forensic Suite & Interactive Dashboard saved to:[/bold bright_green] [bold yellow]{html_path}[/bold yellow]"
        )


@app.command("ja3-db")
def ja3_db_command() -> None:
    """
    List all built-in malicious TLS JA3 / JA3S fingerprints and MITRE ATT&CK mappings.
    """
    console.print(BANNER)
    table = Table(
        title="🔐 Built-In Malicious TLS JA3 & JA3S Threat Intelligence Signatures",
        box=box.ROUNDED,
        border_style="bright_green",
        header_style="bold bright_cyan",
    )
    table.add_column("Type", style="bold")
    table.add_column("MD5 Fingerprint Hash", style="yellow")
    table.add_column("C2 / Malware Family", style="bold bright_green")
    table.add_column("Severity", justify="center")
    table.add_column("Signature Description")

    for md5_hash, meta in JA3_THREAT_DB.items():
        table.add_row(
            meta["type"],
            md5_hash,
            meta["family"],
            _severity_badge(meta["severity"]),
            meta["signature"],
        )
    console.print(table)


if __name__ == "__main__":
    app()
