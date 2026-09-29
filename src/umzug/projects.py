from __future__ import annotations

import configparser
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from typing import Any

from .util import UmzugError, contained, sha256_file
from .git_safety import dangerous_git_config


MAX_MANIFEST_BYTES = 8 * 1024 * 1024

ECOSYSTEM_FILES: dict[str, tuple[str, tuple[str, ...]]] = {
    "pyproject.toml": ("python", ("python", "build-tools")),
    "requirements.txt": ("python", ("python", "build-tools")),
    "Pipfile": ("python", ("python", "build-tools")),
    "package.json": ("node", ("build-tools",)),
    "Cargo.toml": ("rust", ("build-tools",)),
    "go.mod": ("go", ("build-tools",)),
    "CMakeLists.txt": ("cmake", ("build-tools",)),
    "meson.build": ("meson", ("build-tools",)),
    "Makefile": ("make", ("build-tools",)),
    "flake.nix": ("nix", ("build-tools",)),
}

EXECUTION_METADATA = {
    ".github/workflows",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "Dockerfile",
    "compose.yml",
    "docker-compose.yml",
    ".envrc",
}


@dataclass(frozen=True)
class ProjectReport:
    root: str
    manifests: tuple[dict[str, Any], ...]
    ecosystems: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    execution_metadata: tuple[str, ...]
    git: dict[str, Any]
    warnings: tuple[str, ...]
    statement: str = "No project code, hook, build, test, package-manager, or VCS command was executed."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _read_bounded(path: Path) -> str:
    if path.stat(follow_symlinks=False).st_size > MAX_MANIFEST_BYTES:
        raise UmzugError(f"project manifest exceeds limit: {path}")
    return path.read_text(encoding="utf-8", errors="strict")


def inspect_project(root: Path) -> ProjectReport:
    root = root.absolute().resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise UmzugError("project root must be a real directory")
    manifests: list[dict[str, Any]] = []
    ecosystems: set[str] = set()
    capabilities: set[str] = set()
    execution: list[str] = []
    warnings: list[str] = []
    git: dict[str, Any] = {"present": False, "hooks": [], "active_config": [], "submodules": []}

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith((".git/objects/", ".git/refs/", ".git/logs/")):
            continue
        name = path.name
        if path.is_file() and name in ECOSYSTEM_FILES:
            ecosystem, required = ECOSYSTEM_FILES[name]
            ecosystems.add(ecosystem)
            capabilities.update(required)
            row: dict[str, Any] = {
                "path": relative,
                "ecosystem": ecosystem,
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
                "declared_dependencies": [],
            }
            try:
                text = _read_bounded(path)
                if name == "package.json":
                    value = json.loads(text)
                    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                        if isinstance(value.get(section), dict):
                            row["declared_dependencies"].extend(sorted(map(str, value[section].keys())))
                    if isinstance(value.get("scripts"), dict) and value["scripts"]:
                        row["active_scripts"] = sorted(map(str, value["scripts"].keys()))
                        warnings.append(f"package scripts require isolated manual review: {relative}")
                elif name == "requirements.txt":
                    row["declared_dependencies"] = [
                        line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
                    ][:10_000]
                elif name == "go.mod":
                    row["declared_dependencies"] = re.findall(r"(?m)^\s*([A-Za-z0-9._~/-]+)\s+v[0-9]", text)[:10_000]
            except (OSError, UnicodeError, json.JSONDecodeError, UmzugError) as exc:
                row["parse_error"] = str(exc)
                warnings.append(f"manifest not fully parsed: {relative}")
            manifests.append(row)
        if path.is_file() and (
            relative in EXECUTION_METADATA or any(relative.startswith(f"{item}/") for item in EXECUTION_METADATA)
        ):
            execution.append(relative)

    git_dir = root / ".git"
    if git_dir.exists():
        git["present"] = True
        if git_dir.is_file():
            warnings.append("linked Git worktree metadata requires manual path validation")
        elif git_dir.is_dir() and not git_dir.is_symlink():
            hooks = git_dir / "hooks"
            if hooks.is_dir() and not hooks.is_symlink():
                git["hooks"] = sorted(
                    path.name for path in hooks.iterdir() if path.is_file() and not path.name.endswith(".sample")
                )
            for config in (git_dir / "config", git_dir / "config.worktree"):
                if not config.is_file() or config.is_symlink():
                    continue
                try:
                    git["active_config"].extend(dangerous_git_config(_read_bounded(config)))
                except (configparser.Error, OSError, UnicodeError, UmzugError) as exc:
                    warnings.append(f"Git config not fully parsed: {exc}")
            modules = root / ".gitmodules"
            if modules.is_file() and not modules.is_symlink():
                try:
                    text = _read_bounded(modules)
                    git["submodules"] = re.findall(r"(?im)^\s*path\s*=\s*(.+)$", text)
                    if re.search(r"(?im)^\s*url\s*=", text):
                        warnings.append("submodule URLs are network endpoints and are never fetched automatically")
                except (OSError, UnicodeError, UmzugError) as exc:
                    warnings.append(f".gitmodules not fully parsed: {exc}")
    if git["hooks"]:
        warnings.append("active Git hooks are never restored automatically")
    if git["active_config"]:
        warnings.append("active Git filter/command configuration is blocked")
    if execution:
        warnings.append("CI/container/build execution metadata is inert and requires isolated source review")
    return ProjectReport(
        root=str(root),
        manifests=tuple(manifests),
        ecosystems=tuple(sorted(ecosystems)),
        required_capabilities=tuple(sorted(capabilities)),
        execution_metadata=tuple(execution),
        git=git,
        warnings=tuple(warnings),
    )
