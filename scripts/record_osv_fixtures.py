"""Download real OSV records for the PyYAML and Jinja2 examples into the package data."""

import os
import shutil
import tempfile
from pathlib import Path

from agent403.cache import cache_root
from agent403.models import Dependency
from agent403.net import HttpClient
from agent403.osv import OsvClient


def main() -> None:
    destination = Path(__file__).resolve().parents[1] / "src" / "agent403" / "data" / "osv_cache"
    temp_root = Path(tempfile.mkdtemp(prefix="agent403-osv-"))
    os.environ["AGENT403_CACHE_DIR"] = str(temp_root)
    deps = [
        Dependency("pyyaml", "5.3.1", True, ""),
        Dependency("jinja2", "2.10", True, ""),
    ]
    advisories, warnings = OsvClient(HttpClient()).fetch_advisories(deps)
    source = cache_root() / "osv_cache"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    for advisory in advisories:
        print(f"{advisory.package}=={advisory.version}")
        print(f"  id: {advisory.id}")
        print(f"  aliases: {', '.join(advisory.aliases)}")
        print(f"  fixed: {', '.join(advisory.fixed_versions)}")
        print(f"  fix refs: {', '.join(advisory.fix_refs)}")
    for warning in warnings:
        print(f"warning: {warning}")


if __name__ == "__main__":
    main()
