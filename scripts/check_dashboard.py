"""Dashboard JS gate: validates the SERVED bytes, not the source bytes.

Background: DASHBOARD_HTML is a Python string, so any backslash escape in the
source (e.g. \\' or \\n inside inline JS) is consumed by Python before serving
and arrives at the browser broken — while a naive file-level node --check
still passes. This gate fails on the pattern and checks served output.
"""
import re
import subprocess
import sys

sys.path.insert(0, ".")

from app.main import DASHBOARD_HTML

# 1. Forbid backslash escapes inside the dashboard region entirely. Inline JS
#    must use quote styles / data attributes that need no backslashes.
start = DASHBOARD_HTML.find("<script>") + len("<script>")
region = DASHBOARD_HTML[start : DASHBOARD_HTML.find("</script>", start)]
bad = re.findall(r"\\['\"nrtbf]", region)
assert not bad, f"forbidden backslash escapes in served dashboard JS: {bad[:5]}"

# 2. Syntax-check exactly what uvicorn would send.
import tempfile as _tf

with _tf.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
    f.write(region)
    _tmp = f.name
proc = subprocess.run(["node", "--check", _tmp], capture_output=True, text=True)
assert proc.returncode == 0, f"node --check failed:\n{proc.stderr[-2000:]}"
print("dashboard gate ok: no escapes, served JS parses")
