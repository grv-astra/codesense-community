"""Read the package list out of a stored SBOM and rank packages by risk.

Handles the three formats the pipeline accepts: syft JSON (``artifacts``), CycloneDX JSON
(``components``) and SPDX JSON (``packages``). Only name / version / ecosystem are taken.
"""
import json
from pathlib import Path

SEVERITY_ORDER = ("critical", "high", "medium", "low", "negligible", "unknown")


def _type_from_purl(purl):
    # pkg:npm/lodash@4.17.21 -> npm
    if not purl or not str(purl).startswith("pkg:"):
        return ""
    return str(purl)[4:].split("/", 1)[0].split("@", 1)[0].lower()


def _entry(name, version, kind, purl=None):
    # CycloneDX / SPDX only give a coarse component type ("library"); the purl names the ecosystem.
    return {
        "name": name or "",
        "version": version or "",
        "type": _type_from_purl(purl) or (kind or ""),
    }


def _spdx_purl(package):
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def read_inventory(path: Path) -> list[dict]:
    """``[{name, version, type}]`` for every package in the SBOM, in file order."""
    with open(path, encoding="utf-8") as f:
        sbom = json.load(f)
    if "artifacts" in sbom:
        return [_entry(a.get("name"), a.get("version"), a.get("type"), a.get("purl"))
                for a in sbom["artifacts"]]
    if "components" in sbom:
        return [_entry(c.get("name"), c.get("version"), c.get("type"), c.get("purl"))
                for c in sbom["components"]]
    if "packages" in sbom:
        return [_entry(p.get("name"), p.get("versionInfo"), None, _spdx_purl(p))
                for p in sbom["packages"]]
    return []


def worst_severity(severities) -> str:
    present = {(s or "unknown").lower() for s in severities}
    for level in SEVERITY_ORDER:
        if level in present:
            return level
    return "none"


def risk_summary(counts: dict) -> str:
    """One line for the table: '3 vulnerabilities (1 critical, 2 high)' or the clean message."""
    total = sum(counts.values())
    if not total:
        return "No known vulnerabilities."
    parts = [f"{counts[level]} {level}" for level in SEVERITY_ORDER if counts.get(level)]
    noun = "vulnerability" if total == 1 else "vulnerabilities"
    return f"{total} {noun} ({', '.join(parts)})"
