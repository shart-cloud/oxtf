#!/usr/bin/env python3
"""Export Checkov using its Python environment, without building tfscan."""
import runpy
from pathlib import Path

runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "crates/tfscan_py/python/tfscan/checkov.py"),
    run_name="__main__",
)
