"""Where an SBOM scan keeps its files (the SBOM, the cosign bundle, the grype/grant reports).

They used to be written to ``output/<scan_id>`` relative to the process' working directory, which
for the packaged app is whatever folder it was launched from -- so an old scan's files could not be
found again after a launch from somewhere else. New scans write under ``DATA_DIR/sbom-output``;
the old location is still read (and cleaned up) so existing scans keep working where they can.
"""
import shutil
from pathlib import Path

from django.conf import settings

SBOM_FILENAMES = ("sbom-cyclonedx.json", "normalized-sbom.json")
BUNDLE_FILENAME = "sbom.bundle.json"


def output_dir(scan_id) -> Path:
    return Path(settings.DATA_DIR) / "sbom-output" / str(scan_id)


def _legacy_output_dir(scan_id) -> Path:
    return Path("output") / str(scan_id)


def find_file(scan_id, names) -> Path | None:
    """The first of ``names`` that exists for this scan, looking in the current location first."""
    for directory in (output_dir(scan_id), _legacy_output_dir(scan_id)):
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def find_sbom(scan_id) -> Path | None:
    return find_file(scan_id, SBOM_FILENAMES)


def find_bundle(scan_id) -> Path | None:
    return find_file(scan_id, (BUNDLE_FILENAME,))


def remove_artifacts(scan_id) -> None:
    for directory in (output_dir(scan_id), _legacy_output_dir(scan_id)):
        shutil.rmtree(directory, ignore_errors=True)
