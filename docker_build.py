import os
import subprocess
import sys
import urllib.request
import zipfile

from github import Github

os.umask(0o000)
g = Github()

requested_version = os.environ["GHIDRA_VERSION"]
requested_version_name = f"Ghidra {requested_version}"

repo = g.get_repo("NationalSecurityAgency/ghidra")
releases = repo.get_releases()

print(f"Building for {requested_version_name}")

for release in releases:
    if release.title == requested_version_name:
        print(f"Downloading {release.title}...")
        urllib.request.urlretrieve(release.assets[0].browser_download_url, "ghidra.zip")
        break

print("Extracting ghidra.zip...")
with zipfile.ZipFile("ghidra.zip", "r") as zf:
    zf.extractall("../ghidra/")

os.remove("ghidra.zip")

print("Building...")
ret = subprocess.call(
    [
        "gradle",
        f"-PGHIDRA_INSTALL_DIR={os.path.dirname(os.getcwd())}/ghidra/ghidra_{requested_version}_PUBLIC",
    ]
)

sys.exit(ret)
