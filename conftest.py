"""Puts the repository root on sys.path so tests/ can `import app`.

pytest prepends the directory containing each test file, not the rootdir, so
without this every test module fails at import with ModuleNotFoundError.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
