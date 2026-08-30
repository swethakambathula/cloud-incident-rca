"""
CLI runner for Cloud Incident RCA Agent.
"""
import argparse
import os
import sys
import json

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from agents.rca_agent.agent import CloudRCAAgent
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.markdown import Markdown

console = Console(force_terminal=True)


def main():
    parser = argparse.ArgumentParser(description="Cloud Incident Root Cause Analysis (RCA) Agent")
    parser.add_argument(
        "--incident",
        type=str,
        default="data/incidents/incident_001_db_pool.json",
        help="Path to incident JSON file"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Optional path to save RCA report JSON/Markdown output"
    )
    args = parser.parse_args()

    incident_path = os.path.abspath(args.incident)
    if not os.path.exists(incident_path):
        console.print(f"[bold red]Error: Incident file not found at '{incident_path}'[/bold red]")
        return

    console.print(Panel(f"[bold cyan]🔍 Analyzing Cloud Incident: {args.incident}[/bold cyan]"))

    agent = CloudRCAAgent()
    result = agent.analyze_incident(incident_path)

    # Print RCA Report
    console.print(f"\n[bold green]=== ROOT CAUSE ANALYSIS REPORT ===[/bold green]")
    console.print(f"[bold white]Incident ID:[/bold white] {result.incident_id}")
    console.print(f"[bold white]Title:[/bold white] {result.title}")
    console.print(f"[bold white]Root Cause Component:[/bold white] [bold red]{result.root_cause_component}[/bold red]")
    console.print(f"[bold white]Confidence Score:[/bold white] [bold yellow]{result.confidence_score * 100:.1f}%[/bold yellow]")
    console.print(f"\n[bold white]Root Cause Summary:[/bold white]\n{result.root_cause_summary}")

    # Print Causal Chain Tree
    tree = Tree("🔗 [bold cyan]Causal Chain Timeline[/bold cyan]")
    for idx, step in enumerate(result.causal_chain, 1):
        tree.add(f"Step {idx}: {step}")
    console.print("\n", tree)

    # Print Top Evidence
    console.print("\n[bold magenta]📌 Key Evidence Items:[/bold magenta]")
    for ev in result.evidence:
        console.print(f"  • [[bold yellow]{ev.id}[/bold yellow]] [{ev.timestamp}] ({ev.source_service}) - {ev.description}")

    # Print Remediation Steps
    console.print("\n[bold green]🛠️ Recommended Remediation Steps:[/bold green]")
    for r in result.remediation_steps:
        console.print(f"  {r.step_number}. [{r.priority}] {r.action} (Target: {r.target_service})")
        if r.command_or_config:
            console.print(f"     [dim]Command/Config:[/dim]\n     [green]{r.command_or_config}[/green]")

    # Save output if specified
    if args.output:
        out_path = os.path.abspath(args.output)
        with open(out_path, 'w', encoding='utf-8') as f:
            if out_path.endswith('.json'):
                json.dump(result.dict(), f, indent=2)
            else:
                f.write(f"# RCA Report: {result.title}\n\n")
                f.write(f"**Root Cause:** {result.root_cause_summary}\n\n")
                f.write(f"**Component:** {result.root_cause_component}\n\n")
        console.print(f"\n[bold blue]Saved RCA report to {out_path}[/bold blue]")


if __name__ == "__main__":
    main()
