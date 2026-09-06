"""
Phase 1 Evaluation Runner.
Executes the RCA Agent against all 6 synthetic ground-truth incidents
and displays comprehensive evaluation metrics.
"""
import os
import sys

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from evaluation.evaluator import RCAEvaluator

console = Console()


def main():
    console.print(Panel("[bold cyan]Running Phase 1 Ground-Truth RCA Evaluation[/bold cyan]", expand=False))
    evaluator = RCAEvaluator()
    summary = evaluator.run_evaluation()

    table = Table(title="Incident RCA Results vs Ground Truth", show_lines=True)
    table.add_column("Incident ID", style="bold yellow")
    table.add_column("Expected Category", style="cyan")
    table.add_column("Predicted Category", style="magenta")
    table.add_column("Match?", justify="center")
    table.add_column("Confidence", justify="right")
    table.add_column("Evidence Cited", justify="center")
    table.add_column("Contradictory Considered", justify="center")

    for r in summary["results"]:
        match_str = "[bold green]PASS[/bold green]" if r["category_matched"] else "[bold red]FAIL[/bold red]"
        contra_str = "[green]YES[/green]" if r["contradictory_considered"] else "[red]NO[/red]"
        table.add_row(
            r["incident_id"],
            r["expected_category"],
            r["predicted_category"],
            match_str,
            f"{r['confidence_score'] * 100:.1f}%",
            f"{r['valid_evidence_count']} items",
            contra_str
        )

    console.print(table)

    # Summary metrics panel
    metrics_text = (
        f"[bold white]Total Incidents Tested:[/bold white] {summary['total_incidents']}\n"
        f"[bold white]RCA Accuracy:[/bold white] [bold green]{summary['rca_accuracy'] * 100:.1f}%[/bold green]\n"
        f"[bold white]Evidence Precision:[/bold white] [bold green]{summary['evidence_precision'] * 100:.1f}%[/bold green]\n"
        f"[bold white]Confidence Calibration:[/bold white] [bold yellow]{summary['confidence_calibration'] * 100:.1f}%[/bold yellow]\n"
        f"[bold white]Unsupported-Claim Rate:[/bold white] [bold green]{summary['unsupported_claim_rate'] * 100:.1f}%[/bold green]"
    )
    console.print(Panel(metrics_text, title="[bold green]Evaluation Summary Metrics[/bold green]", expand=False))

    if summary["rca_accuracy"] < 1.0 or summary["unsupported_claim_rate"] > 0.0:
        console.print("[bold red]Phase 1 Exit Criteria: FAILED[/bold red]")
        sys.exit(1)
    else:
        console.print("[bold green]Phase 1 Exit Criteria: PASSED (All 6 scenarios diagnosed accurately!)[/bold green]")


if __name__ == "__main__":
    main()
