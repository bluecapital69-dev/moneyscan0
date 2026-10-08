import typer
from rich import print
from .scanner import scan
from .report import write_reports

app = typer.Typer(add_completion=False,
                  help="Passive money-leak scanner for sites you own.")

@app.command()
def main(
    url: str = typer.Argument(..., help="URL to scan (must be yours or authorized)"),
    html_out: str = typer.Option("report.html"),
    json_out: str = typer.Option("report.json"),
):
    print(f"[bold]Scanning[/bold] {url} (passive, authorized testing only)")
    data = scan(url)
    write_reports(data, html_out, json_out)

    print(f"\n[bold]Findings:[/bold] {len(data['findings'])}")
    for f in data["findings"]:
        color = {"critical": "red", "high": "orange1", "medium": "yellow",
                 "low": "green", "info": "dim"}.get(f["severity"], "white")
        print(f"  [{color}]{f['severity'].upper():8}[/{color}] {f['title']}")

    print(f"\nReports: [bold]{html_out}[/bold], [bold]{json_out}[/bold]")

if __name__ == "__main__":
    app()
