"""Run browser layout checks without starting the backend or invoking actions.

Requires Node, Playwright (resolvable via NODE_PATH), and Chrome.
Usage: python scripts/check_shell.py [screenshots-directory]
Set NODE_BINARY to use a Node executable outside PATH.
"""
import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parents[1]
    module = ast.parse((root / "app/main.py").read_text(encoding="utf-8"))
    html = next(
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "DASHBOARD_HTML" for t in node.targets)
    )
    with tempfile.TemporaryDirectory(prefix="rca-shell-") as directory:
        preview = Path(directory) / "dashboard.html"
        preview.write_text(html, encoding="utf-8")
        return subprocess.call([
            os.environ.get("NODE_BINARY", "node"),
            str(root / "scripts/check_shell.cjs"), str(preview), *sys.argv[1:],
        ], cwd=root)


if __name__ == "__main__":
    raise SystemExit(main())
