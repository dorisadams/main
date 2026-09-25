"""Tests for C2PA manifest validator CLI."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "devx" / "validate_c2pa_manifests.py"
FIXTURES = ROOT / "devx" / "fixtures" / "c2pa"


class TestValidateC2PAManifestsCLI(unittest.TestCase):
    def test_cli_passes_bundled_fixtures(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(CLI)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("fixtures passed", proc.stdout)

    def test_cli_single_valid_fixture(self) -> None:
        path = FIXTURES / "valid-c2pa-manifest.json"
        proc = subprocess.run(
            [sys.executable, str(CLI), str(path)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PASS valid-c2pa-manifest.json", proc.stdout)


if __name__ == "__main__":
    unittest.main()
