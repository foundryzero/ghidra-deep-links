#!/usr/bin/python3
import os
import sys
from datetime import datetime
from pathlib import Path

from github import Auth, Github
from github.GithubException import UnknownObjectException

os.umask(0o000)


RELEASE_VERSION = os.environ["RELEASE_TAG"]
ASSET_PATH = os.environ["ASSET_PATH"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]

g = Github(GITHUB_TOKEN)

# TODO: Put this link in here is a cleaner way?
deeplinks_repo = g.get_repo("foundryzero/ghidra-deep-links-private")


try:
    new_release = deeplinks_repo.get_release(RELEASE_VERSION)
except UnknownObjectException as e:
    print(f"Encountered {e} looking for existing release, trying to create new release...")
    new_release = deeplinks_repo.create_git_release(
        RELEASE_VERSION,
        name=f"ghidra-deep-links {RELEASE_VERSION}",
        message="Automated Tagged Release",
        generate_release_notes=True,
    )

new_assets = []

asset_folder = Path(ASSET_PATH)
if asset_folder.is_dir:
    new_assets = [file for file in asset_folder.iterdir()]

# Rename builts assets and add to release
for asset in new_assets:
    new_release.upload_asset(str(asset.absolute()), label=asset.name)

sys.exit(0)
