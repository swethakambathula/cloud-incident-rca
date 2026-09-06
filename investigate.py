"""
CLI Investigation Tool for Google Cloud Production Incidents.
Phase 3: Multi-agent coordinated investigation via Orchestration Workflow.
Usage:
    python investigate.py --service checkout-service --minutes 10
    python investigate.py --service checkout-service --incident-time 2026-09-05T14:30:00Z --window 10 --verbose
    python investigate.py --local-scenario data/incidents/incident_001_db_timeout.json
    python investigate.py --local-scenario data/incidents/incident_001_db_timeout.json --verbose
"""
import os
import sys
import argparse
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

load_dotenv()
console = Console(force_terminal=True)

from tools.correlation import collect_incident_evidence
from orchestration.workflow import InvestigationWorkflow
from orchestration.state import InvestigationState
from schemas.evidence import IncidentEvidence
# Keep backward compat single-agent for --legacy flag
from agents.rca_agent.agent import CloudRCAAgent


def parse_time_window(args):
    # Support --incident-time and --window as per spec, alias to --minutes
    incident_time = getattr(args, "incident_time", None)
    window = getattr(args, "window", None)
    minutes = getattr(args, "minutes", 10)
    if window is not None:
        minutes = window
    return incident_time, minutes


def main():
    parser = argparse.ArgumentParser(
        description="Google Cloud Production Incident Investigation & RCA Agent (Phase 3 Multi-Agent)"
    )
    parser.add_argument("--service", type=str, default=os.getenv("INCIDENT_SERVICE", "checkout-service"))
    parser.add_argument("--project", type=str, default=os.getenv("GOOGLE_CLOUD_PROJECT", "cloud-incident-prod"))
    parser.add_argument("--region", type=str, default=os.getenv("GOOGLE_CLOUD_REGION", "us-central1"))
    parser.add_argument("--minutes", type=int, default=int(os.getenv("DEFAULT_TIME_WINDOW", "10")))
    parser.add_argument("--window", type=int, default=None, help="Alias for --minutes (Phase 3 spec)")
    parser.add_argument("--incident-time", type=str, default=None, help="Incident start time ISO8601 (e.g., 2026-09-05T14:30:00Z)")
    parser.add_argument("--local-scenario", type=str, default=None)
    parser.add_argument("--output-json", type=str, default=None)
    parser.add_argument("--verbose", action="store_true", help="Display detailed agent findings and workflow trace")
    parser.add_argument("--legacy", action="store_true", help="Use legacy single-agent RCA (Phase 2)")
    parser.add_argument("--service-checkout", type=str, default=None, help="Deprecated alias placeholder")

    args = parser.parse_args()
    incident_time, minutes = parse_time_window(args)
    if args.window is not None:
        minutes = args.window

    console.print(Panel.fit(
        f"[bold cyan]🔍 Google Cloud Incident Investigation & RCA Agent - Phase 3 Multi-Agent[/bold cyan]\n"
        f"[dim]Project: {args.project} | Service: {args.service} | Window: {minutes} mins | Verbose: {args.verbose}[/dim]",
        border_style="cyan"
    ))

    # 1. Collect / Load Evidence
    if args.local_scenario:
        scenario_path = os.path.abspath(args.local_scenario)
        if not os.path.exists(scenario_path):
            console.print(f"[bold red]Error: Scenario file not found at '{scenario_path}'[/bold red]")
            sys.exit(1)
        console.print(f"[yellow]Loading local incident scenario:[/yellow] {args.local_scenario}")
        with open(scenario_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        evidence = IncidentEvidence(**data)
    else:
        console.print(f"[yellow]Collecting telemetry evidence from Google Cloud APIs...[/yellow]")
        # If incident_time provided, use it to define window
        if incident_time:
            try:
                start_dt = datetime.fromisoformat(incident_time.replace("Z", "+00:00"))
                end_dt = start_dt  # correlation will compute window internally; for simplicity pass via start
                # we pass incident_start to collect_incident_evidence
                evidence = collect_incident_evidence(
                    project_id=args.project,
                    service_name=args.service,
                    incident_start=start_dt.isoformat(),
                    minutes_window=minutes,
                    region=args.region
                )
            except Exception as e:
                console.print(f"[red]Invalid incident-time format: {e}[/red]")
                sys.exit(1)
        else:
            evidence = collect_incident_evidence(
                project_id=args.project,
                service_name=args.service,
                minutes_window=minutes,
                region=args.region
            )

    # 2. Run investigation
    if args.legacy:
        console.print(f"[yellow]Executing legacy single-agent RCA...[/yellow]\n")
        agent = CloudRCAAgent()
        rca = agent.analyze(evidence)
        # Display single-agent output (backward compat)
        _display_single_rca(evidence, rca)
        if args.output_json:
            with open(args.output_json, "w", encoding="utf-8") as f:
                f.write(rca.model_dump_json(indent=2))
            console.print(f"\n[bold dim]Exported RCA report to {args.output_json}[/bold dim]")
        return

    console.print(f"[yellow]Executing Multi-Agent Investigation Workflow...[/yellow]\n")
    workflow = InvestigationWorkflow()
    state: InvestigationState = workflow.run(evidence, verbose=args.verbose)

    report = state.final_report
    if not report:
        console.print("[bold red]Investigation failed to produce final report[/bold red]")
        sys.exit(1)

    # 3. Display
    if args.verbose:
        _display_verbose(state)
    else:
        _display_summary(state)

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))
            # Also export full state trace if verbose requested via .trace.json
        console.print(f"\n[bold dim]Exported RCA report to {args.output_json}[/bold dim]")
        trace_path = args.output_json.replace(".json", ".trace.json")
        with open(trace_path, "w", encoding="utf-8") as f:
            f.write(state.model_dump_json(indent=2))
        console.print(f"[bold dim]Exported investigation trace to {trace_path}[/bold dim]")


def _display_summary(state: InvestigationState):
    report = state.final_report
    evidence = state.incident_evidence
    sev_style = {"P1": "bold red", "P2": "bold yellow", "P3": "bold blue"}.get(evidence.severity, "bold white")
    console.print(f"[bold white]INCIDENT:[/bold white] {report.incident_id}")
    console.print(f"[bold white]Severity:[/bold white] [{sev_style}]{evidence.severity}[/{sev_style}]")
    console.print(f"[bold white]Affected Service:[/bold white] {', '.join(report.affected_services)}")
    console.print(f"\n[bold green]Root Cause:[/bold green]")
    console.print(f"  {report.root_cause}")
    console.print(f"[bold white]Confidence:[/bold white] [bold yellow]{report.confidence * 100:.1f}%[/bold yellow]")

    console.print("\n[bold green]Supporting Evidence:[/bold green]")
    for e in report.supporting_evidence:
        console.print(f"  [green]✔[/green] {e}")

    console.print("\n[bold magenta]Contradictory Evidence:[/bold magenta]")
    if report.contradictory_evidence:
        for ce in report.contradictory_evidence:
            console.print(f"  [magenta]✖[/magenta] {ce}")
    else:
        console.print(f"  [dim]None significant[/dim]")

    # Blast Radius
    br = report.blast_radius
    console.print(f"\n[bold yellow]Blast Radius:[/bold yellow] [{br.classification}] {br.estimated_scope}")
    if br.affected_endpoints:
        console.print(f"  Endpoints: {', '.join(br.affected_endpoints)}")
    if br.affected_revision:
        console.print(f"  Revision: {br.affected_revision}")

    console.print(f"\n[bold green]Recommended Action:[/bold green]")
    console.print(f"  👉 {report.recommended_next_action}")

    if report.missing_evidence:
        console.print("\n[bold blue]Missing Evidence:[/bold blue]")
        for m in report.missing_evidence:
            console.print(f"  - {m}")

    # Optional: show rejected hypotheses succinctly
    if report.rejected_hypotheses:
        console.print("\n[bold dim]Rejected Hypotheses:[/bold dim]")
        for rh in report.rejected_hypotheses[:2]:
            console.print(f"  - {rh.hypothesis_id} {rh.validation_status} ({rh.adjusted_confidence:.2f}): {rh.critic_reasoning[:100]}")


def _display_verbose(state: InvestigationState):
    report = state.final_report
    console.print(Panel("VERBOSE INVESTIGATION TRACE", style="cyan"))

    # Supervisor Plan
    console.print("\n[bold cyan]Supervisor Plan[/bold cyan]")
    for i, step in enumerate(state.investigation_plan, 1):
        status = "✔" if step in state.completed_tasks else "◐" if step in state.pending_tasks else "○"
        console.print(f"  {i}. [{status}] {step}")

    # Agent Findings grouped
    from collections import defaultdict
    by_agent = defaultdict(list)
    for f in state.agent_findings:
        by_agent[f.agent_name].append(f)
    for agent_name, findings in by_agent.items():
        console.print(f"\n[bold yellow]{agent_name} Findings ({len(findings)})[/bold yellow]")
        for f in findings:
            console.print(f"  • [{f.evidence_strength.value}] {f.summary}")
            for sup in f.supporting_evidence[:2]:
                console.print(f"      [dim]{sup}[/dim]")
            if f.missing_information:
                console.print(f"      [red]Missing: {', '.join(f.missing_information[:2])}[/red]")

    # Knowledge
    if state.knowledge_findings:
        console.print(f"\n[bold magenta]Knowledge Findings ({len(state.knowledge_findings)})[/bold magenta]")
        for kf in state.knowledge_findings:
            console.print(f"  • {kf.source_id} ({kf.source_type}) similarity {kf.similarity_score:.2f}")
            console.print(f"    {kf.title} - {kf.relevant_excerpt_summary[:120]}")
            console.print(f"    Pattern: {kf.associated_failure_pattern} checks: {', '.join(kf.recommended_checks[:2])}")

    # Hypotheses
    console.print(f"\n[bold green]RCA Hypotheses ({len(state.hypotheses)})[/bold green]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Conf", justify="right")
    table.add_column("Reasoning")
    for h in state.hypotheses:
        table.add_row(h.hypothesis_id, h.root_cause_category, f"{h.confidence_score:.2f}", h.reasoning_summary[:80])
    console.print(table)

    # Critic
    console.print(f"\n[bold red]Critic Decisions ({len(state.validated_hypotheses)+len(state.rejected_hypotheses)})[/bold red]")
    table2 = Table(show_header=True, header_style="bold red")
    table2.add_column("ID")
    table2.add_column("Status")
    table2.add_column("Adj Conf", justify="right")
    table2.add_column("Reasoning")
    for v in state.validated_hypotheses + state.rejected_hypotheses:
        style = "green" if v.accepted else "red"
        table2.add_row(v.hypothesis_id, f"[{style}]{v.validation_status.value}[/{style}]", f"{v.adjusted_confidence:.2f}", v.critic_reasoning[:90])
    console.print(table2)

    # Confidence changes
    console.print("\n[bold yellow]Confidence Changes[/bold yellow]")
    for h in state.hypotheses:
        # find validation
        v = next((x for x in state.validated_hypotheses + state.rejected_hypotheses if x.hypothesis_id == h.hypothesis_id), None)
        if v:
            delta = v.adjusted_confidence - h.confidence_score
            sym = "↑" if delta > 0 else "↓" if delta < 0 else "→"
            console.print(f"  {h.hypothesis_id}: {h.confidence_score:.2f} {sym} {v.adjusted_confidence:.2f} ({v.validation_status.value})")

    # Timeline
    console.print(f"\n[bold cyan]Incident Timeline[/bold cyan]")
    for te in report.timeline:
        console.print(f"  {te.timestamp} [{te.event_type}] {te.description} (src: {te.source})")

    # Blast Radius
    br = report.blast_radius
    console.print(f"\n[bold yellow]Blast Radius - Final RCA[/bold yellow]")
    console.print(f"  Classification: {br.classification}")
    console.print(f"  Scope: {br.estimated_scope}")

    # Final report text
    console.print(f"\n[bold green]Final RCA[/bold green]")
    console.print(f"  {report.root_cause} (conf {report.confidence:.2f})")
    console.print(f"  Recommended: {report.recommended_next_action}")

    # Investigation trace summary
    console.print(f"\n[bold dim]InvestigationTrace: rounds={state.trace.investigation_rounds} agents={len(state.trace.agent_traces)} rejected={state.trace.hypotheses_rejected_count} final_conf={state.trace.final_confidence:.2f}[/bold dim]")
    for at in state.trace.agent_traces:
        console.print(f"  [dim]{at.agent_name} {at.duration_ms:.0f}ms tools={at.tools_invoked} evidence={at.evidence_items_count}[/dim]")


def _display_single_rca(evidence, rca):
    sev_style = {"P1": "bold red", "P2": "bold yellow", "P3": "bold blue"}.get(evidence.severity, "bold white")
    console.print(f"[bold white]Incident ID:[/bold white] {rca.incident_id}")
    console.print(f"[bold white]Severity:[/bold white] [{sev_style}]{evidence.severity}[/{sev_style}]")
    console.print(f"[bold white]Affected Service:[/bold white] {', '.join(rca.affected_services)}")
    console.print("\n[bold cyan]Symptoms Observed:[/bold cyan]")
    for s in evidence.symptoms:
        console.print(f"  • {s}")
    console.print(f"\n[bold green]Root Cause Diagnosis:[/bold green]")
    console.print(f"  [bold underline]{rca.root_cause_category.upper()}[/bold underline]: {rca.root_cause}")
    console.print(f"[bold white]Confidence:[/bold white] [bold yellow]{rca.confidence_score * 100:.1f}%[/bold yellow]")
    console.print("\n[bold green]Supporting Evidence Cited:[/bold green]")
    for e in rca.evidence:
        console.print(f"  [green]✔[/green] {e}")
    console.print("\n[bold magenta]Contradictory Evidence Analyzed:[/bold magenta]")
    for ce in rca.contradictory_evidence:
        console.print(f"  [magenta]✖[/magenta] {ce}")
    console.print(f"\n[bold yellow]Blast Radius:[/bold yellow]\n  {rca.blast_radius}")
    risk_style = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(rca.remediation_risk, "white")
    console.print(f"\n[bold green]Recommended Action:[/bold green] [{risk_style}][Risk: {rca.remediation_risk}][/{risk_style}]")
    console.print(f"  👉 {rca.recommended_action}")
    if rca.additional_checks_required:
        console.print("\n[bold blue]Additional Checks Required:[/bold blue]")
        for chk in rca.additional_checks_required:
            console.print(f"  🔍 {chk}")


if __name__ == "__main__":
    main()
