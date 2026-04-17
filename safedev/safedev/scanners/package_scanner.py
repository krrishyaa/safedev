"""
package_scanner.py
──────────────────
Pre-download security checks + optional real install.

Flow:
  1. Blocklist check  (instant — no network)
  2. Typosquat check  (instant — no network)
  3. If both pass → download & scan source
  4. If source scan passes → actually pip/npm install
"""

import os
import sys
import shutil
import tarfile
import zipfile
import tempfile
import subprocess
from pathlib import Path

from safedev.utils.rule_engine import load_rules, scan_directory
from safedev.utils.reporter    import build_report
from safedev.utils.blocklist   import check_blocklist
from safedev.utils.typosquat   import check_typosquat


# ── Helpers ────────────────────────────────────────────────────

def _pre_download_checks(package_name: str, ecosystem: str) -> dict | None:
    """
    Run blocklist + typosquat checks.
    Returns an error report dict if blocked, else None (all clear).
    """
    # 1. Blocklist
    bl = check_blocklist(package_name, ecosystem)
    if bl:
        return {
            "target":          package_name,
            "ecosystem":       ecosystem,
            "score":           10,
            "risk_label":      "BLOCKED",
            "total_findings":  1,
            "findings":        [],
            "blocked":         True,
            "block_reason":    f"KNOWN MALICIOUS: {bl['reason']}",
        }

    # 2. Typosquat
    ts = check_typosquat(package_name, ecosystem)
    if ts:
        return {
            "target":          package_name,
            "ecosystem":       ecosystem,
            "score":           8,
            "risk_label":      "BLOCKED",
            "total_findings":  1,
            "findings":        [],
            "blocked":         True,
            "block_reason":    (
                f"TYPOSQUATTING DETECTED ({ts['confidence']} confidence): "
                f"\"{package_name}\" looks like \"{ts['similar_to']}\" "
                f"(edit distance {ts['distance']}). "
                f"Did you mean: {ts['similar_to']}?"
            ),
        }

    return None  # all clear


# ── Public API ─────────────────────────────────────────────────

def scan_pip_package(package_name: str, do_install: bool = False) -> dict:
    """
    Check + optionally install a pip package.
    If do_install=True and package is safe, runs: pip install <package>
    """
    # Step 1: pre-download checks (instant)
    blocked = _pre_download_checks(package_name, "pip")
    if blocked:
        return blocked

    # Step 2: download & scan source
    rules   = load_rules()
    tmp_dir = tempfile.mkdtemp(prefix="safedev_pip_")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "download",
             "--no-deps", "--dest", tmp_dir, package_name],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return {
                "target": package_name, "ecosystem": "pip",
                "score": 0, "risk_label": "ERROR",
                "total_findings": 0, "findings": [],
                "error": result.stderr.strip(),
            }

        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        for fname in os.listdir(tmp_dir):
            fpath = os.path.join(tmp_dir, fname)
            if fname.endswith(".whl"):
                with zipfile.ZipFile(fpath, "r") as zf:
                    zf.extractall(extract_dir)
            elif fname.endswith((".tar.gz", ".tgz")):
                with tarfile.open(fpath, "r:gz") as tf:
                    tf.extractall(extract_dir)
            elif fname.endswith(".zip"):
                with zipfile.ZipFile(fpath, "r") as zf:
                    zf.extractall(extract_dir)

        findings = scan_directory(extract_dir, rules)
        report   = build_report(package_name, findings, ecosystem="pip")

        # Step 3: if safe and user wants install → actually install
        if do_install and report["score"] < 5:
            install = subprocess.run(
                [sys.executable, "-m", "pip", "install", package_name],
                capture_output=True, text=True,
            )
            report["installed"]      = install.returncode == 0
            report["install_output"] = install.stdout.strip() or install.stderr.strip()

        return report

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def scan_npm_package(package_name: str, do_install: bool = False) -> dict:
    """
    Check + optionally install an npm package.
    If do_install=True and package is safe, runs: npm install <package>
    """
    # Step 1: pre-download checks (instant)
    blocked = _pre_download_checks(package_name, "npm")
    if blocked:
        return blocked

    # Step 2: download & scan source
    rules   = load_rules()
    tmp_dir = tempfile.mkdtemp(prefix="safedev_npm_")

    try:
        result = subprocess.run(
            ["npm", "pack", package_name, "--pack-destination", tmp_dir],
            capture_output=True, text=True, cwd=tmp_dir,
        )
        if result.returncode != 0:
            return {
                "target": package_name, "ecosystem": "npm",
                "score": 0, "risk_label": "ERROR",
                "total_findings": 0, "findings": [],
                "error": result.stderr.strip(),
            }

        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        for fname in os.listdir(tmp_dir):
            if fname.endswith(".tgz"):
                fpath = os.path.join(tmp_dir, fname)
                with tarfile.open(fpath, "r:gz") as tf:
                    tf.extractall(extract_dir)

        findings = scan_directory(extract_dir, rules)
        report   = build_report(package_name, findings, ecosystem="npm")

        # Step 3: if safe and user wants install → actually install
        if do_install and report["score"] < 5:
            install = subprocess.run(
                ["npm", "install", package_name],
                capture_output=True, text=True,
            )
            report["installed"]      = install.returncode == 0
            report["install_output"] = install.stdout.strip() or install.stderr.strip()

        return report

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
