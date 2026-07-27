import os
import re
from pathlib import Path
from urllib.parse import unquote

MARKDOWN_LINK = re.compile(r"!?\[[^\]]*]\((?P<target>[^)]+)\)")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:")
EXCLUDED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "graphify-out",
    "reports",
}
OPTIONAL_README_DIRECTORIES = {Path(".github")}


def _markdown_files() -> list[Path]:
    files: list[Path] = []
    for directory, subdirectories, names in os.walk("."):
        subdirectories[:] = [
            name
            for name in subdirectories
            if name not in EXCLUDED_DIRECTORIES
            and (not name.startswith(".") or name == ".github")
            and not name.endswith(".egg-info")
        ]
        files.extend(Path(directory) / name for name in names if name.endswith(".md"))
    return files


def _local_link_paths(document: Path) -> set[Path]:
    paths: set[Path] = set()
    for match in MARKDOWN_LINK.finditer(document.read_text(encoding="utf-8")):
        raw_target = match.group("target").strip().strip("<>")
        target = raw_target.split(maxsplit=1)[0]
        if not target or target.startswith("#") or target.startswith(EXTERNAL_SCHEMES):
            continue
        path_text = unquote(target.split("#", 1)[0].split("?", 1)[0])
        paths.add((document.parent / path_text).resolve())
    return paths


def test_all_local_markdown_links_are_relative_and_resolve():
    broken: list[str] = []

    for document in _markdown_files():
        content = document.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(content):
            raw_target = match.group("target").strip().strip("<>")
            target = raw_target.split(maxsplit=1)[0]
            if not target or target.startswith("#") or target.startswith(EXTERNAL_SCHEMES):
                continue
            path_text = unquote(target.split("#", 1)[0].split("?", 1)[0])
            linked_path = Path(path_text)
            if linked_path.is_absolute():
                broken.append(f"{document}: absolute link {raw_target}")
                continue
            if not (document.parent / linked_path).exists():
                broken.append(f"{document}: missing {raw_target}")

    assert not broken, "Broken local Markdown links:\n" + "\n".join(broken)


def test_every_project_directory_has_a_bidirectionally_linked_readme():
    file_directories = {path.parent for path in _markdown_files()}
    file_directories.update(
        path.parent
        for path in Path(".").rglob("*")
        if path.is_file()
        and not any(part in EXCLUDED_DIRECTORIES for part in path.parts)
        and not any(part.endswith(".egg-info") for part in path.parts)
    )
    project_directories = {Path(".")}
    for directory in file_directories:
        project_directories.update([directory, *directory.parents])
    project_directories = {
        directory for directory in project_directories if directory == Path(".") or not directory.is_absolute()
    }
    root = Path(".")
    failures: list[str] = []

    for directory in sorted(project_directories):
        readme = directory / "README.md"
        if directory in OPTIONAL_README_DIRECTORIES:
            assert not readme.exists()
            continue
        if not readme.exists():
            failures.append(f"{directory}: missing README.md")
            continue
        if directory != root:
            parent = directory.parent
            parent_readme = parent / "README.md"
            while not parent_readme.exists() and parent != root:
                parent = parent.parent
                parent_readme = parent / "README.md"
            if parent_readme.resolve() not in _local_link_paths(readme):
                failures.append(f"{readme}: does not link to {parent_readme}")
            if parent_readme.exists() and readme.resolve() not in _local_link_paths(parent_readme):
                failures.append(f"{parent_readme}: does not link to {readme}")

    assert not failures, "Invalid README hierarchy:\n" + "\n".join(failures)


def test_documentation_and_its_directory_index_link_to_each_other():
    failures: list[str] = []

    for document in _markdown_files():
        if document.name == "README.md":
            continue
        directory_readme = document.parent / "README.md"
        if document.parent != Path(".") and directory_readme.resolve() not in _local_link_paths(document):
            failures.append(f"{document}: does not link to {directory_readme}")
        if document.resolve() not in _local_link_paths(directory_readme):
            failures.append(f"{directory_readme}: does not link to {document}")

    assert not failures, "Documentation outside the bidirectional index:\n" + "\n".join(failures)
