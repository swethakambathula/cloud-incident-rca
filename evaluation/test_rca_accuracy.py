"""
Evaluation Script for RCA Accuracy Benchmark.
Compares CloudRCAAgent output against golden test cases.
"""
import os
import sys
import json
from typing import List

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from agents.rca_agent.agent import CloudRCAAgent
from agents.rca_agent.schemas import EvaluationMetric
from rich.console import Console
from rich.table import Table

console = Console(force_terminal=True)


def run_evaluation() -> List[EvaluationMetric]:
    """Runs accuracy benchmarks against golden cases."""
    agent = CloudRCAAgent()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    golden_path = os.path.join(base_dir, "evaluation", "golden_cases.json")

    with open(golden_path, 'r', encoding='utf-8') as f:
        cases = json.load(f)

    metrics: List[EvaluationMetric] = []

    for case in cases:
        inc_file = os.path.join(base_dir, case["incident_file"])
        if not os.path.exists(inc_file):
            continue

        result = agent.analyze_incident(inc_file)

        # Component matching check
        component_matched = (
            case["expected_component"].lower() in result.root_cause_component.lower() or
            result.root_cause_component.lower() in case["expected_component"].lower()
        )

        # Keyword recall check
        summary_text = (result.root_cause_summary + " " + " ".join(result.causal_chain)).lower()
        matched_kw = [kw for kw in case["expected_keywords"] if kw.lower() in summary_text]
        keyword_recall = len(matched_kw) / len(case["expected_keywords"]) if case["expected_keywords"] else 1.0

        root_cause_matched = component_matched and (keyword_recall >= 0.5)

        metric = EvaluationMetric(
            incident_id=result.incident_id,
            root_cause_matched=root_cause_matched,
            component_matched=component_matched,
            confidence=result.confidence_score,
            evidence_recall_score=keyword_recall,
            precision_score=1.0 if component_matched else 0.0,
            notes=f"Matched {len(matched_kw)}/{len(case['expected_keywords'])} keywords. Component: {result.root_cause_component}"
        )
        metrics.append(metric)

    _print_benchmark_table(metrics)
    return metrics


def _print_benchmark_table(metrics: List[EvaluationMetric]):
    table = Table(title="📊 Cloud Incident RCA Accuracy Benchmark Results")
    table.add_column("Incident ID", style="cyan", no_wrap=True)
    table.add_column("Component Match", style="magenta")
    table.add_column("RCA Pass", style="bold green")
    table.add_column("Keyword Recall", style="yellow")
    table.add_column("Confidence Score", style="blue")
    table.add_column("Notes", style="white")

    total_pass = 0
    for m in metrics:
        if m.root_cause_matched:
            total_pass += 1
        table.add_row(
            m.incident_id,
            "✅ YES" if m.component_matched else "❌ NO",
            "✅ PASS" if m.root_cause_matched else "❌ FAIL",
            f"{m.evidence_recall_score*100:.1f}%",
            f"{m.confidence*100:.1f}%",
            m.notes
        )

    console.print(table)
    overall_accuracy = (total_pass / len(metrics) * 100) if metrics else 0
    console.print(f"\n[bold green]Overall RCA Benchmark Accuracy: {overall_accuracy:.1f}%[/bold green]\n")


if __name__ == "__main__":
    run_evaluation()
