import asyncio
import csv
import json
import re
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from scrapers.wayback import search_wayback_archives
from scrapers.crtsh import enumerate_subdomains

app = typer.Typer(help="OSINT-Leak-Radar — Wayback exposure + subdomain enumeration")
console = Console()

SEVERITY = [
    (re.compile(r'id_rsa|id_dsa|\.pem$'),                          "CRITICAL", "Private Key"),
    (re.compile(r'\.env$|\.env\.'),                                 "CRITICAL", "Env File"),
    (re.compile(r'\.sql(\.gz|\.zip|\.tar)?$|db_backup|dump\.sql'), "HIGH",     "Database Dump"),
    (re.compile(r'credentials\.xml|credentials\.json'),            "HIGH",     "Credentials File"),
    (re.compile(r'config\.php|wp-config\.php'),                    "HIGH",     "CMS Config"),
    (re.compile(r'\.log$|access\.log|error\.log'),                 "MEDIUM",   "Log File"),
    (re.compile(r'backup|archive|old|bkp'),                        "LOW",      "Backup/Archive"),
    (re.compile(r'config\.yml|config\.yaml|settings\.py'),         "LOW",      "Config File"),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def classify(urls: List[str]) -> List[dict]:
    results = []
    for url in urls:
        u = url.lower()
        for pattern, severity, leak_type in SEVERITY:
            if pattern.search(u):
                results.append({"url": url, "severity": severity, "type": leak_type})
                break
    return sorted(results, key=lambda x: SEVERITY_ORDER[x["severity"]])


def severity_color(s: str) -> str:
    return {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(s, "white")


def write_output(findings: list, subdomains: list, path: str):
    p = Path(path)
    if p.suffix == ".csv":
        with open(p, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["severity", "type", "url"])
            w.writeheader()
            w.writerows(findings)
    else:
        with open(p, "w") as f:
            json.dump({"exposures": findings, "subdomains": subdomains}, f, indent=2)
    console.print(f"[dim]Saved to {path}[/dim]")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain (e.g. company.com)"),
    subdomains: bool = typer.Option(True,  "--subdomains/--no-subdomains", help="Enumerate subdomains via crt.sh"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to file (.json or .csv)"),
    live_only: bool = typer.Option(False, "--live-only", help="Show only live subdomains"),
):
    """Scan a domain for credential exposures and enumerate subdomains."""
    console.print(f"\n[bold red]OSINT-LEAK-RADAR[/bold red] → [yellow]{target}[/yellow]\n")

    # --- Wayback scan ---
    console.print("[bold][ 1/2 ] Querying Wayback Machine CDX...[/bold]")
    with console.status("Fetching archived URLs..."):
        urls = search_wayback_archives(target)
    console.print(f"  Found [cyan]{len(urls)}[/cyan] archived URLs")

    findings = classify(urls)
    if findings:
        table = Table(title="Potential Exposures", border_style="red", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type", width=18)
        table.add_column("Archived URL")
        for f in findings[:30]:
            table.add_row(f"[{severity_color(f['severity'])}]{f['severity']}[/]", f["type"], f["url"])
        console.print(table)
    else:
        console.print("  [green]No sensitive file patterns matched.[/green]")

    # --- crt.sh subdomain enumeration ---
    subdomain_results = []
    if subdomains:
        console.print("\n[bold][ 2/2 ] Enumerating subdomains via crt.sh + DNS...[/bold]")
        with console.status("Fetching certificate transparency logs..."):
            subdomain_results = asyncio.run(enumerate_subdomains(target))

        if live_only:
            subdomain_results = [s for s in subdomain_results if s["live"]]

        if subdomain_results:
            stable = Table(title="Subdomains", border_style="blue", show_lines=True)
            stable.add_column("Status", width=8)
            stable.add_column("Subdomain")
            stable.add_column("IP")
            for s in subdomain_results:
                status = "[green]LIVE[/green]" if s["live"] else "[dim]dead[/dim]"
                stable.add_row(status, s["subdomain"], s["ip"] or "—")
            console.print(stable)
            live_count = sum(1 for s in subdomain_results if s["live"])
            console.print(f"  [cyan]{live_count}[/cyan] live / [dim]{len(subdomain_results) - live_count} dead[/dim]")
        else:
            console.print("  [dim]No subdomains found in certificate logs.[/dim]")

    # --- Output ---
    if output:
        write_output(findings, subdomain_results, output)

    console.print(f"\n[dim]Results are from public archives/CT logs. Verify manually before acting.[/dim]\n")


if __name__ == "__main__":
    app()
