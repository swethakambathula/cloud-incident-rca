"""Test execution on the patched branch (Part 11)."""
import subprocess
from typing import List


def run_tests(repo_path: str, tests: List[str], timeout_s: int = 180) -> dict:
    """Run pytest node-ids. Returns {passed, output}. Never creates PRs on failure."""
    cmd = ["pytest", "-q"] + tests
    proc = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True,
                          timeout=timeout_s)
    output = (proc.stdout + "\n" + proc.stderr)[-4000:]
    return {"passed": proc.returncode == 0, "output": output,
            "returncode": proc.returncode}
