import os
import sys

# Ensure root cloud-incident-rca directory is in Python module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.logging_tools import get_error_logs

logs = get_error_logs(
    project_id="project-f14fda81-0a51-4c38-9f3",
    service_name="demo-service",
)

for log in logs[:10]:
    print("=" * 80)
    print(log)