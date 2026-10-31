from agent403.deps import load_dependencies, normalize_name, parse_pyproject, parse_requirements


def test_normalize_name() -> None:
    assert normalize_name("PyYAML_Foo.bar") == "pyyaml-foo-bar"


def test_requirement_lines(tmp_path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(
        "\n".join(
            [
                "# comment",
                "",
                "PyYAML==5.3.1",
                "Rich===13.0.0",
                "requests>=2  # inline",
                "packaging==23.*",
                "Some.Pkg[extra]==1.2.3 ; python_version < '3.12'",
                "--index-url https://pypi.org/simple",
                "-e ./localpkg",
                "git+https://github.com/org/demo.git@main#egg=demo",
                "Left @ https://example.com/left.whl",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    deps, warnings = parse_requirements(path)
    by_name = {dep.name: dep for dep in deps}
    assert by_name["pyyaml"].pinned is True
    assert by_name["pyyaml"].version == "5.3.1"
    assert by_name["rich"].pinned is True
    assert by_name["rich"].version == "13.0.0"
    assert by_name["requests"].pinned is False
    assert by_name["packaging"].pinned is False
    assert by_name["some-pkg"].pinned is True
    assert by_name["some-pkg"].version == "1.2.3"
    assert by_name["demo"].pinned is False
    assert by_name["left"].pinned is False
    assert "localpkg" not in by_name
    assert any("not pinned" in warning for warning in warnings)
    assert any("URL or VCS" in warning for warning in warnings)


def test_include_and_cycle(tmp_path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("-r b.txt\npyyaml==5.3.1\n", encoding="utf-8")
    second.write_text("-r a.txt\njinja2==2.10\n", encoding="utf-8")
    deps, warnings = parse_requirements(first)
    names = [dep.name for dep in deps]
    assert names == ["jinja2", "pyyaml"]
    assert any("repeated requirements file" in warning for warning in warnings)


def test_pyproject_and_conflict(tmp_path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("PyYAML==5.3.1\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\ndependencies = ["PyYAML==5.4", "requests>=2"]\n',
        encoding="utf-8",
    )
    direct, direct_warnings = parse_pyproject(project / "pyproject.toml")
    assert direct[0].name == "pyyaml"
    assert direct[0].pinned is True
    assert direct[1].pinned is False
    assert any("not pinned" in warning for warning in direct_warnings)
    deps, warnings = load_dependencies(project, None)
    pyyaml = next(dep for dep in deps if dep.name == "pyyaml")
    assert pyyaml.version == "5.3.1"
    assert any("version conflict" in warning for warning in warnings)


def test_override_replaces_discovery(tmp_path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
    other = tmp_path / "other.txt"
    other.write_text("jinja2==2.10\n", encoding="utf-8")
    deps, _warnings = load_dependencies(project, other)
    assert [dep.name for dep in deps] == ["jinja2"]
