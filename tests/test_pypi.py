import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from agent403.net import HttpClient
from agent403.pypi import (
    DigestMismatchError,
    UnsafeArchiveError,
    fetch,
    find_local,
    safe_extract_tar,
    safe_extract_zip,
)


def _serve(monkeypatch: pytest.MonkeyPatch, filename: str, data: bytes, packagetype: str) -> None:
    project = {
        "urls": [
            {
                "packagetype": packagetype,
                "filename": filename,
                "url": "https://example.test/archive",
                "digests": {"sha256": hashlib.sha256(data).hexdigest()},
            }
        ]
    }
    monkeypatch.setattr(HttpClient, "get_json", lambda self, url: project)
    monkeypatch.setattr(HttpClient, "get_bytes", lambda self, url: data)


def test_find_local_top_level_and_requires(tmp_path: Path) -> None:
    site = tmp_path / "site"
    dist_info = site / "PyYAML-5.3.1.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "top_level.txt").write_text("yaml\n", encoding="utf-8")
    (dist_info / "METADATA").write_text("Requires-Dist: Requests>=2\n", encoding="utf-8")
    found = find_local("PyYAML", "5.3.1", [site])
    assert found is not None
    assert found.origin == "local"
    assert found.root == site
    assert found.import_names == ["yaml"]
    assert found.requires_dist == ["requests"]


def test_record_fallback(tmp_path: Path) -> None:
    site = tmp_path / "site"
    dist_info = site / "demo-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "RECORD").write_text(
        "mymod.py,sha256=abc,1\npkg/__init__.py,sha256=abc,1\n"
        "demo-1.0.dist-info/METADATA,sha256=abc,1\n",
        encoding="utf-8",
    )
    found = find_local("demo", "1.0", [site])
    assert found is not None
    assert found.import_names == ["mymod", "pkg"]


def test_wheel_requires_and_top_level(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("coolpkg/__init__.py", "")
        bundle.writestr("coolpkg-1.0.dist-info/top_level.txt", "coolpkg\n")
        bundle.writestr(
            "coolpkg-1.0.dist-info/METADATA",
            "Requires-Dist: Requests>=2.28\nRequires-Dist: rich (>=13)\n",
        )
        bundle.writestr("coolpkg-1.0.dist-info/RECORD", "")
    _serve(monkeypatch, "coolpkg-1.0-py3-none-any.whl", archive.getvalue(), "bdist_wheel")
    dist = fetch("CoolPkg", "1.0", offline=False, sites=[])
    assert dist.origin == "wheel"
    assert dist.import_names == ["coolpkg"]
    assert dist.requires_dist == ["requests", "rich"]
    assert (dist.root / "coolpkg").is_dir()


def test_sdist_lib3_layout(monkeypatch: pytest.MonkeyPatch) -> None:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
        _add_bytes(bundle, "Cool-1.0/PKG-INFO", b"Requires-Dist: Packaging>=23\n")
        _add_bytes(bundle, "Cool-1.0/lib3/coolpkg/__init__.py", b"")
        _add_bytes(bundle, "Cool-1.0/tests/ignoreme/__init__.py", b"")
        _add_bytes(bundle, "Cool-1.0/docs/docpkg/__init__.py", b"")
    _serve(monkeypatch, "Coolpkg-1.0.tar.gz", archive.getvalue(), "sdist")
    dist = fetch("coolpkg", "1.0", offline=False, sites=[])
    assert dist.origin == "sdist"
    assert dist.root.name == "lib3"
    assert dist.import_names == ["coolpkg"]
    assert dist.requires_dist == ["packaging"]


def test_zip_slip(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../evil.txt", "nope")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(archive, tmp_path / "out")


def test_tar_parent_and_symlink(tmp_path: Path) -> None:
    parent = tmp_path / "parent.tar.gz"
    with tarfile.open(parent, "w:gz") as bundle:
        info = tarfile.TarInfo("../evil.txt")
        payload = b"nope"
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    with pytest.raises(UnsafeArchiveError):
        safe_extract_tar(parent, tmp_path / "out-parent")

    link = tmp_path / "link.tar.gz"
    with tarfile.open(link, "w:gz") as bundle:
        info = tarfile.TarInfo("inside")
        info.type = tarfile.SYMTYPE
        info.linkname = "target"
        bundle.addfile(info)
    with pytest.raises(UnsafeArchiveError):
        safe_extract_tar(link, tmp_path / "out-link")


def test_sha256_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    project = {
        "urls": [
            {
                "packagetype": "bdist_wheel",
                "filename": "demo-1.0-py3-none-any.whl",
                "url": "https://example.test/demo.whl",
                "digests": {"sha256": "0" * 64},
            }
        ]
    }
    monkeypatch.setattr(HttpClient, "get_json", lambda self, url: project)
    monkeypatch.setattr(HttpClient, "get_bytes", lambda self, url: b"not-the-archive")
    with pytest.raises(DigestMismatchError):
        fetch("demo", "1.0", offline=False, sites=[])


@pytest.mark.network
def test_live_jinja2_import_names(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT403_CACHE_DIR", str(tmp_path / "live-cache"))
    dist = fetch("jinja2", "2.10", offline=False, sites=[])
    assert dist.import_names == ["jinja2"]


def _add_bytes(bundle: tarfile.TarFile, name: str, payload: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    bundle.addfile(info, io.BytesIO(payload))
