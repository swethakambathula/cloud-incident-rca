import os
import sys

# Ensure root cloud-incident-rca directory is in Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.monitoring_tools import (
    get_request_count,
    get_error_rate,
    get_request_latency,
    compare_baseline_to_incident
)

if __name__ == "__main__":
    project_id = "project-f14fda81-0a51-4c38-9f3"
    service_name = "demo-service"

    print("--- Request Count ---")
    print(get_request_count(project_id, service_name, minutes=30))

    print("\n--- Error Rate ---")
    print(get_error_rate(project_id, service_name, minutes=30))

    print("\n--- Latency ---")
    print(get_request_latency(project_id, service_name, minutes=30))

    print("\n--- Baseline vs Incident Comparison ---")
    print(compare_baseline_to_incident(project_id, service_name))
