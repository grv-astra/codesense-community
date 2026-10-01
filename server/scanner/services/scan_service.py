import os
import shutil
import zipfile
import uuid
from django.conf import settings
from scanner.utils.github_downloader import download_github_repo_zip
 
 
async def scan_github_repo(token, username, repo, branch):
    scan_id = str(uuid.uuid4())
 
    base_dir = os.path.join(settings.BASE_DIR, "media", "scans")
    os.makedirs(base_dir, exist_ok=True)
 
    zip_path = os.path.join(base_dir, f"{scan_id}.zip")
    extract_path = os.path.join(base_dir, scan_id)
    os.makedirs(extract_path, exist_ok=True)
 
    zip_bytes = await download_github_repo_zip(token, username, repo, branch)
 
    with open(zip_path, "wb") as f:
        f.write(zip_bytes.read())
 
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_path)

    # See local/api_app/views/scan_views.py's ScanCreateView.post() for why:
    # a .github/ folder anywhere in the scanned tree can silently zero out
    # OpenGrep's rule-matching for the entire directory scan.
    _STRIPPED_DIR_NAMES = {".git", ".github"}
    for root, dirs, _files in os.walk(extract_path, topdown=True):
        for d in list(dirs):
            if d in _STRIPPED_DIR_NAMES:
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                dirs.remove(d)

    return {
        "folder_path": extract_path
    }