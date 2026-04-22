import typer
from rich.console import Console
from rich.table import Table
from scrapers.wayback import search_wayback_archives
import re
from typing import List

app = typer.Typer(help="The OSINT Automated Corporate Exposure Engine")
console = Console()

SENSITIVE_PATTERNS = [
    (re.compile(r'\.env$'),              "Env File Leak"),
    (re.compile(r'\.sql(\.gz|\.zip)?$'), "SQL Dump"),
    (re.compile(r'db_backup'),           "Database Backup"),
    (re.compile(r'\.pem$'),              "Private Certificate"),
    (re.compile(r'id_rsa'),              "SSH Private Key"),
    (re.compile(r'credentials\.xml'),    "Credentials File"),
    (re.compile(r'config\.php'),         "Config File"),
]

def classify_urls(urls: List[str]) -> List[dict]:
    """
    Pattern-based classifier — matches URLs against known sensitive file signatures
    and returns those likely to contain credentials or internal data.
    """
    results = []
    for url in urls:
        for pattern, leak_type in SENSITIVE_PATTERNS:
            if pattern.search(url.lower()):
                results.append({"url": url, "type": leak_type})
                break
    return results


@app.command()
def scan(target: str = typer.Argument(..., help="Target domain (e.g. company.com)")):
    """Hunt Wayback Machine archives for sensitive files exposed by the target domain."""
    console.print(f"[bold red]OSINT-LEAK-RADAR[/bold red] scanning: [yellow]{target}[/yellow]")

    with console.status("[bold green]Querying Wayback CDX API..."):
        urls = search_wayback_archives(target)
        if not urls:
            console.print("[dim]No historical data found in Wayback archives.[/dim]")
            return

    with console.status("[bold blue]Classifying results..."):
        leaks = classify_urls(urls)

    if not leaks:
        console.print("[green]No sensitive file patterns matched.[/green]")
        return

    console.print(f"\n[bold red]{len(leaks)} potential exposure(s) found[/bold red]")

    table = Table(title=f"Potential Exposures — {target}", border_style="red")
    table.add_column("Type", style="magenta")
    table.add_column("Archived URL", style="green")

    for leak in leaks[:20]:
        table.add_row(leak["type"], leak["url"])

    console.print(table)
    console.print(
        "\n[dim]Results are based on Wayback Machine archives — "
        "verify manually before treating as active exposures.[/dim]"
    )


if __name__ == "__main__":
    app()
