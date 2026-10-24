"""SBOM scan reports: the dependency list, CSV/JSON exports and the SBOM / signed-bundle downloads."""
import csv
import io
import json
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from django.http import HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from local.auth_app.permissions.decorators import require_permission
from scanner.services import sbom_artifacts, sbom_inventory
from scanner.services.tools import cosign_paths

from ..models.sbom_models import SbomModel

_VERIFY_TEXT = """\
Verify this SBOM with cosign (https://github.com/sigstore/cosign):

  cosign verify-blob {sbom} --key cosign.pub --bundle {bundle} --insecure-ignore-tlog=true

The signature was made offline with the key of the Code Sense installation that ran the scan
(cosign.pub is its public half). --insecure-ignore-tlog is needed because nothing is uploaded to a
public transparency log.
"""


def _csv_cell(value):
    """Text cells that a spreadsheet would read as a formula get a leading quote (CSV injection)."""
    if value is None:
        return ""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _csv_response(filename, header, rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow([_csv_cell(v) for v in row])
    # The BOM makes Excel read the file as UTF-8 (package descriptions are not always ASCII).
    response = HttpResponse("﻿" + buffer.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _json_response(filename, document):
    response = HttpResponse(json.dumps(document, indent=2), content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _vulnerability_rows(findings):
    for f in findings:
        yield [
            f["package"]["name"], f["package"]["version"], f["package"]["type"], f["cve_id"],
            f["severity"], f["cvss_score"], f["description"], "; ".join(f["fix_versions"]),
            f["created_at"],
        ]


_VULNERABILITY_HEADER = ["Package", "Version", "Type", "CVE / Advisory", "Severity", "CVSS Score",
                         "Description", "Fix Versions", "Created At"]


def _license_rows(findings):
    for f in findings:
        lic = f["license"]
        yield [
            f["package"]["name"], f["package"]["version"], f["package"]["type"], lic.get("id"),
            lic.get("risk_category"), lic.get("risk_level"), lic.get("osi_approved"), f["decision"],
            "; ".join(f["locations"]), lic.get("reference"), f["created_at"],
        ]


_LICENSE_HEADER = ["Package", "Version", "Type", "License", "Risk Category", "Risk Level",
                   "OSI Approved", "Decision", "Locations", "Reference", "Created At"]


class SbomExportView(APIView):
    """GET ?kind=vulnerabilities|licenses&file_format=csv|json -- the scan's findings as a file.

    Not ``format``: DRF reserves that query parameter to pick a renderer and answers 404 for csv.
    """

    @require_permission("create_report")
    def get(self, request, scan_id):
        scan = SbomModel.find_by_id(scan_id)
        if not scan:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        kind = request.query_params.get("kind", "vulnerabilities")
        fmt = request.query_params.get("file_format", "csv")
        if kind not in ("vulnerabilities", "licenses") or fmt not in ("csv", "json"):
            return Response(
                {"error": "kind must be vulnerabilities or licenses and file_format must be csv or json"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if kind == "vulnerabilities":
            items = SbomModel.find_sbom_findings_all(scan_id)
            header, rows = _VULNERABILITY_HEADER, _vulnerability_rows(items)
        else:
            items = SbomModel.find_license_findings_all(scan_id)
            header, rows = _LICENSE_HEADER, _license_rows(items)

        filename = f"sbom_{scan['id']}_{kind}.{fmt}"
        if fmt == "csv":
            return _csv_response(filename, header, rows)
        return _json_response(filename, {
            "scan_id": scan["id"],
            "scan_name": scan["scan_name"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(items),
            kind: items,
        })


class SbomDownloadView(APIView):
    """GET -- ``sbom``: the SBOM file itself; ``signed``: it zipped with its cosign bundle and key."""

    @require_permission("create_report")
    def get(self, request, scan_id, kind):
        scan = SbomModel.find_by_id(scan_id)
        if not scan:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        sbom_path = sbom_artifacts.find_sbom(scan_id)
        if sbom_path is None:
            return Response({"error": "The SBOM file for this scan is no longer available."},
                            status=status.HTTP_404_NOT_FOUND)

        if kind == "sbom":
            response = HttpResponse(sbom_path.read_bytes(), content_type="application/json")
            response["Content-Disposition"] = f'attachment; filename="sbom_{scan["id"]}.json"'
            return response

        if kind != "signed":
            return Response({"error": "kind must be sbom or signed"}, status=status.HTTP_400_BAD_REQUEST)

        signing = scan.get("signing") or {}
        bundle_path = sbom_artifacts.find_bundle(scan_id)
        if not signing.get("signed") or bundle_path is None:
            return Response({"error": "This scan was not signed."}, status=status.HTTP_404_NOT_FOUND)

        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(sbom_path, sbom_path.name)
            zf.write(bundle_path, bundle_path.name)
            public_key = Path(cosign_paths()[1])
            if public_key.is_file():
                zf.write(public_key, "cosign.pub")
            zf.writestr("VERIFY.txt", _VERIFY_TEXT.format(sbom=sbom_path.name, bundle=bundle_path.name))
        response = HttpResponse(archive.getvalue(), content_type="application/zip")
        response["Content-Disposition"] = f'attachment; filename="sbom_{scan["id"]}_signed.zip"'
        return response


class SbomDependenciesView(APIView):
    """GET -- every package of the scan with its worst vulnerability severity and its licenses."""

    @require_permission("view_findings")
    def get(self, request, scan_id):
        scan = SbomModel.find_by_id(scan_id)
        if not scan:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)
        try:
            page = max(int(request.query_params.get("page", 1)), 1)
            limit = max(min(int(request.query_params.get("limit", 10)), 200), 1)
        except ValueError:
            return Response({"error": "page and limit must be numbers"}, status=status.HTTP_400_BAD_REQUEST)
        search = (request.query_params.get("search") or "").strip().lower()

        severities = defaultdict(lambda: defaultdict(int))        # (name, version) -> severity -> n
        for f in SbomModel.find_sbom_findings_all(scan_id):
            pkg = f["package"]
            severities[(pkg["name"], pkg["version"])][f["severity"] or "unknown"] += 1
        licenses = defaultdict(list)                              # (name, version) -> [license id]
        for f in SbomModel.find_license_findings_all(scan_id):
            pkg = f["package"]
            lic = f["license"].get("id")
            if lic and lic not in licenses[(pkg["name"], pkg["version"])]:
                licenses[(pkg["name"], pkg["version"])].append(lic)

        inventory = None
        sbom_path = sbom_artifacts.find_sbom(scan_id)
        if sbom_path is not None:
            try:
                inventory = sbom_inventory.read_inventory(sbom_path)
            except (OSError, ValueError):
                inventory = None
        inventory_complete = inventory is not None
        if inventory is None:
            # The SBOM file is gone (a scan from before artifacts had a fixed home, or cleaned up):
            # all that is left is the packages that have a finding.
            known = {}
            for f in SbomModel.find_sbom_findings_all(scan_id):
                pkg = f["package"]
                known.setdefault((pkg["name"], pkg["version"]), pkg["type"])
            for f in SbomModel.find_license_findings_all(scan_id):
                pkg = f["package"]
                known.setdefault((pkg["name"], pkg["version"]), pkg["type"])
            inventory = [{"name": n, "version": v, "type": t} for (n, v), t in known.items()]

        rows = []
        for index, pkg in enumerate(inventory):
            key = (pkg["name"], pkg["version"])
            counts = dict(severities.get(key, {}))
            rows.append({
                "id": f"{scan['id']}:{index}",
                "package_name": pkg["name"],
                "dependence_version": pkg["version"],
                "package_type": pkg["type"],
                "risk_rating": sbom_inventory.worst_severity(counts) if counts else "none",
                "risk_summary": sbom_inventory.risk_summary(counts),
                "vulnerabilities": sum(counts.values()),
                "licenses": licenses.get(key, []),
            })

        if search:
            rows = [r for r in rows if search in " ".join(
                [r["package_name"], r["dependence_version"], r["package_type"], r["risk_rating"],
                 *r["licenses"]]).lower()]
        order = {level: i for i, level in enumerate(sbom_inventory.SEVERITY_ORDER)}
        order["none"] = len(order)
        rows.sort(key=lambda r: (order.get(r["risk_rating"], len(order)), r["package_name"].lower()))

        total = len(rows)
        skip = (page - 1) * limit
        return Response({
            "dependencies": rows[skip:skip + limit],
            "pagination": {"total": total, "page": page, "limit": limit,
                           "pages": (total + limit - 1) // limit},
            "inventory_complete": inventory_complete,
        }, status=status.HTTP_200_OK)
