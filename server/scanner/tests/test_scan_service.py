import io
import os
import shutil
import tempfile
import zipfile
from unittest import IsolatedAsyncioTestCase, mock

from django.test import override_settings

from scanner.services.scan_service import scan_github_repo


def _zip_bytes_with_vcs_dirs():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("file.txt", "hello")
        zf.writestr(".github/workflows/ci.yml", "name: ci")
    return buf.getvalue()


class ScanGithubRepoVcsStripTests(IsolatedAsyncioTestCase):
    """Regression coverage: a .github/ folder anywhere in a scanned tree
    silently zeroes out OpenGrep's rule-matching for the entire directory
    scan (confirmed via a real DVWA scan -- 0 findings with .github present,
    90 with it stripped, identical rules/content otherwise). The GitHub
    zipball API includes .github/ just like any other tracked directory, so
    this path needs the same strip as the zip-upload path in scan_views.py."""

    async def test_github_dir_stripped_after_extraction(self):
        base_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base_dir, True)
        with override_settings(BASE_DIR=base_dir), mock.patch(
            "scanner.services.scan_service.download_github_repo_zip",
            new=mock.AsyncMock(return_value=io.BytesIO(_zip_bytes_with_vcs_dirs())),
        ):
            result = await scan_github_repo("t", "u", "r", "main")
        folder_path = result["folder_path"]
        self.assertTrue(os.path.isfile(os.path.join(folder_path, "file.txt")))
        self.assertFalse(os.path.isdir(os.path.join(folder_path, ".github")))
