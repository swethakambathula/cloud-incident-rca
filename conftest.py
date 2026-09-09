"""Root conftest: ensure repo root is importable under `pytest` and `python -m pytest`.

Bare `pytest` (as CI runs it) does not put CWD on sys.path, and several test
dirs (tests/, tests/integration/, tests/unit/) have no __init__.py chain, so
`import agents` / `import tools` failed at collection with ModuleNotFoundError.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
