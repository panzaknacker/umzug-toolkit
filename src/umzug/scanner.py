"""offline inspection, approval and restore bound to exact bytes and metadata.

the built-in inspector never executes input or extracts archives. external
file/ClamAV/YARA checks use argument vectors, resource limits and explicit
trust anchors for tools and rules. passing checks does not prove malware freedom.

strict_external requires bubblewrap, its trusted tool hash and a working
namespace probe. there is no direct-execution fallback. promotion, approval
and confirmed restore remain separate decisions.
"""

from __future__ import annotations

import bz2
import configparser
import contextlib
import ctypes
import dataclasses
import datetime as _datetime
import enum
import errno
import hashlib
import hmac
import io
import json
import lzma
import os
import re
import resource
import selectors
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import unicodedata
import zipfile
import zlib
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Mapping, Sequence

from .limits import MAX_CANDIDATE_OBJECTS
from .git_safety import dangerous_git_config
from .util import UmzugError, atomic_replace, minimal_bwrap_runtime
from .scan_formats import (
    _mime_agrees,
    _rpm_header_end,
    _shannon_entropy,
    _unsafe_archive_path,
    _unsafe_link_from_member,
    _validate_png,
)


SCHEMA_VERSION = 1
_CHUNK_SIZE = 1024 * 1024
_MAX_SCANNER_TOOL_BYTES = 128 * 1024 * 1024
_MAX_TRUST_TREE_DEPTH = 64


class Stage(str, enum.Enum):
    """trust zones.  movement is only permitted from left to right."""

    SOURCE = "SOURCE"
    QUARANTINE = "QUARANTINE"
    SANITIZED = "SANITIZED"
    APPROVED = "APPROVED"
    RESTORED = "RESTORED"


class Severity(str, enum.Enum):
    INFO = "info"
    REVIEW = "review"
    BLOCKER = "blocker"


class ScannerError(RuntimeError):
    """base class for scanner and pipeline failures."""


class IntegrityError(ScannerError):
    """the candidate no longer matches the inspected manifest."""


class ApprovalError(ScannerError):
    """an approval was absent, incomplete, or unsafe."""


class UnsafeInputError(ScannerError):
    """the input cannot be copied without changing its meaning safely."""


@dataclasses.dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    rule: str
    path: str
    message: str
    evidence: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "rule": self.rule,
            "path": self.path,
            "message": self.message,
            "evidence": dict(self.evidence),
        }


@dataclasses.dataclass(frozen=True)
class FileRecord:
    path: str
    kind: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime_ns: int
    nlink: int
    sha256: str | None = None
    link_target: str | None = None
    detected_type: str | None = None
    hardlink_group: str | None = None

    def manifest_dict(self) -> dict[str, object]:
        # detected_type is deliberately excluded: the manifest binds input,
        # while the report records the conclusion drawn from that input.
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "mtime_ns": self.mtime_ns,
            "nlink": self.nlink,
            "sha256": self.sha256,
            "link_target": self.link_target,
            "hardlink_group": self.hardlink_group,
        }

    def to_dict(self) -> dict[str, object]:
        result = self.manifest_dict()
        result["detected_type"] = self.detected_type
        return result


@dataclasses.dataclass(frozen=True)
class ToolEvidence:
    name: str
    path: str | None
    version: str | None
    sha256: str | None
    expected_sha256: str | None
    available: bool
    verified: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class _MaterialSnapshot:
    configured_path: str
    source_path: str | None
    snapshot_path: Path | None
    sha256: str | None
    expected_sha256: str | None
    verified: bool
    is_directory: bool
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class _ScannerTrustSnapshots:
    tools: Mapping[str, Path]
    yara_rules: tuple[_MaterialSnapshot, ...]
    clam_signatures: tuple[_MaterialSnapshot, ...]


@dataclasses.dataclass(frozen=True)
class ExternalScanResult:
    tool: str
    path: str
    returncode: int | None
    status: str
    output: str
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ScanPolicy:
    """resource and trust policy for a scan.

    the defaults intentionally make a scan non-approvable until all external
    evidence is configured.  unit tests and deliberately reduced environments
    can opt out with ``strict_external=False``; that fact remains in the report.
    """

    max_files: int = MAX_CANDIDATE_OBJECTS
    max_inspect_bytes: int = 64 * 1024 * 1024
    max_archive_input_bytes: int = 256 * 1024 * 1024
    max_archive_member_bytes: int = 64 * 1024 * 1024
    max_archive_expanded_bytes: int = 1024 * 1024 * 1024
    max_archive_members: int = 10_000
    max_archive_depth: int = 4
    max_compression_ratio: float = 200.0
    max_text_bytes: int = 16 * 1024 * 1024
    max_external_output_bytes: int = 16 * 1024
    external_timeout_seconds: int = 120
    max_external_address_space_bytes: int = 1024 * 1024 * 1024
    max_external_cpu_seconds: int = 90
    max_external_processes: int = 64
    max_external_open_files: int = 256
    run_external_scanners: bool = True
    strict_external: bool = True
    require_verified_external_material: bool = True
    external_isolation_backend: str = "bubblewrap"
    allow_unisolated_external_in_relaxed_mode: bool = False
    require_secure_source_mount: bool = True
    required_source_mount_options: tuple[str, ...] = ("ro", "noexec", "nodev", "nosuid")
    required_external_scanners: tuple[str, ...] = ("file", "clamscan", "yara")
    trusted_tool_hashes: Mapping[str, str] = dataclasses.field(default_factory=dict)
    yara_rule_paths: tuple[Path, ...] = ()
    trusted_yara_rule_hashes: Mapping[str, str] = dataclasses.field(default_factory=dict)
    clam_signature_paths: tuple[Path, ...] = ()
    trusted_clam_signature_hashes: Mapping[str, str] = dataclasses.field(default_factory=dict)
    allow_executable_files_after_review: bool = False
    block_all_unknown_binary: bool = True
    allow_cross_filesystems: bool = False

    def __post_init__(self) -> None:
        positive = {
            "max_files": self.max_files,
            "max_inspect_bytes": self.max_inspect_bytes,
            "max_archive_input_bytes": self.max_archive_input_bytes,
            "max_archive_member_bytes": self.max_archive_member_bytes,
            "max_archive_expanded_bytes": self.max_archive_expanded_bytes,
            "max_archive_members": self.max_archive_members,
            "max_archive_depth": self.max_archive_depth,
            "max_text_bytes": self.max_text_bytes,
            "max_external_output_bytes": self.max_external_output_bytes,
            "external_timeout_seconds": self.external_timeout_seconds,
            "max_external_address_space_bytes": self.max_external_address_space_bytes,
            "max_external_cpu_seconds": self.max_external_cpu_seconds,
            "max_external_processes": self.max_external_processes,
            "max_external_open_files": self.max_external_open_files,
        }
        invalid = [name for name, value in positive.items() if value <= 0]
        if invalid or self.max_compression_ratio <= 0:
            raise ValueError(f"policy limits must be positive: {', '.join(invalid)}")
        if self.external_isolation_backend not in {"bubblewrap", "none"}:
            raise ValueError("external_isolation_backend must be 'bubblewrap' or 'none'")


@dataclasses.dataclass(frozen=True)
class ScanReport:
    schema_version: int
    scan_id: str
    scanned_at: str
    root: str
    stage: Stage
    policy: Mapping[str, object]
    records: tuple[FileRecord, ...]
    findings: tuple[Finding, ...]
    manifest_sha256: str
    tools: Mapping[str, ToolEvidence]
    external_results: tuple[ExternalScanResult, ...]
    disclaimer: str = "A completed scan reduces risk but cannot prove that content is malware-free."

    @property
    def blockers(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is Severity.BLOCKER)

    @property
    def reviews(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is Severity.REVIEW)

    def unresolved(self, accepted_findings: Iterable[str] = ()) -> tuple[Finding, ...]:
        accepted = set(accepted_findings)
        return self.blockers + tuple(f for f in self.reviews if f.id not in accepted)

    def can_promote(self, accepted_findings: Iterable[str] = ()) -> bool:
        return not self.unresolved(accepted_findings)

    def can_approve(self, accepted_findings: Iterable[str] = ()) -> bool:
        return self.stage is Stage.SANITIZED and self.can_promote(accepted_findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "scanned_at": self.scanned_at,
            "root": self.root,
            "stage": self.stage.value,
            "policy": dict(self.policy),
            "records": [record.to_dict() for record in self.records],
            "findings": [finding.to_dict() for finding in self.findings],
            "manifest_sha256": self.manifest_sha256,
            "tools": {name: evidence.to_dict() for name, evidence in self.tools.items()},
            "external_results": [result.to_dict() for result in self.external_results],
            "disclaimer": self.disclaimer,
        }

    def write_json(self, destination: Path) -> None:
        destination = Path(destination)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=True)
        _atomic_write_text(destination, payload + "\n", mode=0o600)


@dataclasses.dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    actor: str
    reason: str
    expected_manifest_sha256: str
    accepted_findings: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class ApprovalRecord:
    schema_version: int
    candidate: str
    actor: str
    reason: str
    approved_at: str
    source_stage: Stage
    manifest_sha256: str
    approved_manifest_sha256: str
    accepted_findings: tuple[str, ...]
    report_scan_id: str
    report_sha256: str
    ingest_provenance_sha256: str
    promotion_sha256: str
    source_manifest_sha256: str
    source_snapshot_manifest_sha256: str
    quarantine_manifest_sha256: str
    sanitized_manifest_sha256: str
    quarantine_report_scan_id: str
    quarantine_report_sha256: str
    promotion_accepted_findings: tuple[str, ...]
    approval_sha256: str

    def to_dict(self) -> dict[str, object]:
        result = dataclasses.asdict(self)
        result["source_stage"] = self.source_stage.value
        return result


@dataclasses.dataclass(frozen=True)
class IngestResult:
    candidate: str
    source_report: ScanReport
    quarantine_report: ScanReport


@dataclasses.dataclass
class _ArchiveBudget:
    members: int = 0
    expanded_bytes: int = 0


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\bgh[opsu]_[A-Za-z0-9]{30,255}\b")),
    (
        "generic_token",
        re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{16,}"),
    ),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}")),
)

_ENDPOINT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s<>\"']+")),
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    ("onion", re.compile(r"(?i)\b[a-z2-7]{16,56}\.onion\b")),
)

_SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("download_exec", re.compile(r"(?i)(?:curl|wget)\b[^\n|;&]{0,500}(?:\||&&|;)\s*(?:sh|bash|python|perl|ruby)\b")),
    ("shell_network", re.compile(r"(?i)(?:/dev/tcp/|\bncat?\b|\bsocat\b|\breverse[_ -]?shell\b)")),
    ("dynamic_eval", re.compile(r"(?i)\b(?:eval|exec)\s*\([^\n]{0,300}(?:base64|decode|decompress|fromhex)")),
    ("shell_spawn", re.compile(r"(?i)(?:os\.system\s*\(|subprocess\.[A-Za-z]+\([^\n]{0,300}shell\s*=\s*True)")),
    ("persistence", re.compile(r"(?i)(?:/etc/(?:cron|systemd|init)|\.config/autostart|rc\.local|authorized_keys)")),
    (
        "kernel_boot_change",
        re.compile(
            r"(?i)(?:update-initramfs|mkinitcpio|dracut|grub-install|efibootmgr|insmod|modprobe|/lib/modules|/boot/)"
        ),
    ),
)

_ACTIVE_CONFIG_DIRECTIVES: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "systemd": (
        ("exec", re.compile(r"(?im)^\s*Exec(?:Start|StartPre|StartPost|Reload|Stop|StopPost|Condition)\s*=")),
        (
            "timer",
            re.compile(r"(?im)^\s*On(?:Calendar|ActiveSec|BootSec|StartupSec|UnitActiveSec|UnitInactiveSec)\s*="),
        ),
    ),
    "cron": (
        (
            "schedule",
            re.compile(r"(?m)^\s*(?![#;])(?:@(?:reboot|hourly|daily|weekly|monthly|yearly)|(?:\S+\s+){5,6}\S+)"),
        ),
    ),
    "desktop": (
        ("exec", re.compile(r"(?im)^\s*(?:TryExec|Exec|X-GNOME-Autostart-Delay)\s*=")),
        ("dbus-activation", re.compile(r"(?im)^\s*DBusActivatable\s*=\s*true\s*$")),
    ),
    "ssh-client": (
        ("proxy-command", re.compile(r"(?im)^\s*ProxyCommand\s+")),
        ("match-exec", re.compile(r"(?im)^\s*Match\b[^\n]*\bexec\b")),
        ("local-command", re.compile(r"(?im)^\s*(?:LocalCommand|PermitLocalCommand)\s+")),
        ("known-hosts-command", re.compile(r"(?im)^\s*KnownHostsCommand\s+")),
    ),
    "make": (
        ("recipe", re.compile(r"(?m)^\t+\S")),
        ("shell-function", re.compile(r"\$\(\s*shell\b")),
        ("include", re.compile(r"(?m)^\s*-?include\s+")),
        ("shell-assignment", re.compile(r"(?m)^\s*[A-Za-z0-9_.-]+\s*!=\s*")),
    ),
    "nix": (
        ("build-command", re.compile(r"\b(?:runCommand|runCommandLocal|mkDerivation)\b")),
        ("fetch", re.compile(r"\b(?:builtins\.)?fetch(?:url|Tarball|Git|Tree)?\b")),
        ("exec", re.compile(r"\bbuiltins\.exec\b")),
    ),
    "ci": (
        ("run", re.compile(r"(?im)^\s*-?\s*(?:run|script|command|powershell|bash)\s*:")),
        ("external-action", re.compile(r"(?im)^\s*-?\s*uses\s*:")),
    ),
    "editor-task": (("command", re.compile(r'(?i)"(?:command|program|preLaunchTask|postDebugTask)"\s*:')),),
    "udev": (
        ("run", re.compile(r"(?im)(?:^|,)\s*RUN(?:\{[^}]+\})?\s*(?:\+?=)")),
        ("program", re.compile(r"(?im)(?:^|,)\s*(?:PROGRAM|IMPORT\{program\})\s*=")),
        ("systemd-wants", re.compile(r'(?i)ENV\{"?SYSTEMD_WANTS"?\}\s*(?:\+?=)')),
    ),
}


def _active_config_categories(rel: str, filename: str, text: str) -> list[tuple[str, bool, tuple[str, ...]]]:
    """classify path-triggered code/config without treating absence of a regex hit as safety."""

    lowered = rel.casefold().replace("\\", "/")
    normalized = lowered[2:] if lowered.startswith("./") else lowered
    rooted = "/" + normalized.lstrip("/")
    basename = filename.casefold()
    categories: list[tuple[str, bool]] = []
    shell_names = {
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zlogin",
        ".zshenv",
        "config.fish",
    }
    if basename in shell_names or ("/.config/fish/conf.d/" in rooted and basename.endswith(".fish")):
        categories.append(("shell-startup", True))
    if basename.endswith((".service", ".timer", ".socket", ".path")):
        categories.append(("systemd", False))
    periodic_cron_path = any(
        token in rooted for token in ("/cron.hourly/", "/cron.daily/", "/cron.weekly/", "/cron.monthly/")
    )
    if "/cron.d/" in rooted or periodic_cron_path or basename in {"crontab", "anacrontab"}:
        categories.append(("cron", periodic_cron_path))
    if basename.endswith(".desktop"):
        categories.append(("desktop", "/autostart/" in rooted))
    if "/.ssh/config" in rooted or rooted.endswith("/ssh_config") or "/ssh/ssh_config.d/" in rooted:
        categories.append(("ssh-client", False))
    if basename == ".envrc":
        categories.append(("direnv", True))
    if basename in {"makefile", "gnumakefile"} or basename.endswith(".mk"):
        categories.append(("make", False))
    if basename.endswith(".nix"):
        categories.append(("nix", False))
    if (
        "/.github/workflows/" in rooted
        or "/.github/actions/" in rooted
        or "/.circleci/" in rooted
        or basename
        in {
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
            "jenkinsfile",
            ".drone.yml",
            ".drone.yaml",
            ".woodpecker.yml",
            ".woodpecker.yaml",
            "azure-pipelines.yml",
            "azure-pipelines.yaml",
        }
    ):
        categories.append(("ci", False))
    if (
        rooted.endswith("/.vscode/tasks.json")
        or rooted.endswith("/.vscode/launch.json")
        or "/.idea/runconfigurations/" in rooted
    ):
        categories.append(("editor-task", False))
    if basename.endswith(".rules") and "/udev/rules.d/" in rooted:
        categories.append(("udev", False))
    if "/networkmanager/dispatcher.d/" in rooted or "/networkd-dispatcher/" in rooted:
        categories.append(("network-dispatcher", True))

    result: list[tuple[str, bool, tuple[str, ...]]] = []
    for category, inherently_executed in categories:
        indicators = tuple(
            name for name, pattern in _ACTIVE_CONFIG_DIRECTIVES.get(category, ()) if pattern.search(text)
        )
        result.append((category, inherently_executed or bool(indicators), indicators))
    return result


_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{256,}={0,2}(?![A-Za-z0-9+/])")
_HEX_BLOB = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{512,}(?![0-9a-f])")
_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".jar",
    ".war",
    ".apk",
    ".docx",
    ".xlsx",
    ".pptx",
    ".tar",
    ".tgz",
    ".tbz",
    ".tbz2",
    ".txz",
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".7z",
    ".rar",
    ".deb",
    ".rpm",
    ".ar",
    ".a",
}
_EXECUTABLE_EXTENSIONS = {".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".exe", ".dll", ".so", ".bin", ".run"}
_DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx", ".rtf"}


def _now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _finding(
    severity: Severity,
    rule: str,
    path: str,
    message: str,
    **evidence: object,
) -> Finding:
    stable = json.dumps(
        {"rule": rule, "path": path, "message": message, "evidence": evidence},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return Finding(
        id=hashlib.sha256(stable).hexdigest()[:24],
        severity=severity,
        rule=rule,
        path=path,
        message=message,
        evidence=evidence,
    )


def _canonical_json_hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_self_hashed_receipt(
    path: Path,
    *,
    hash_field: str,
    receipt_type: str,
) -> dict[str, object]:
    """load a canonical self-hashed receipt without accepting legacy shapes."""

    try:
        raw, complete = _read_file_nofollow(path, 64 * 1024 * 1024)
        if not complete:
            raise IntegrityError(f"{receipt_type} receipt exceeds its size limit")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"{receipt_type} receipt is missing or invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"{receipt_type} receipt must be a JSON object")
    supplied = value.get(hash_field)
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise IntegrityError(f"{receipt_type} receipt has no valid {hash_field}")
    payload = dict(value)
    del payload[hash_field]
    observed = _canonical_json_hash(payload)
    if not hmac.compare_digest(supplied, observed):
        raise IntegrityError(f"{receipt_type} receipt self-hash mismatch")
    if payload.get("schema_version") != SCHEMA_VERSION or payload.get("receipt_type") != receipt_type:
        raise IntegrityError(f"{receipt_type} receipt has an unsupported schema or type")
    return value


def _manifest_hash(records: Sequence[FileRecord]) -> str:
    return _canonical_json_hash([record.manifest_dict() for record in records])


def _atomic_write_text(path: Path, text: str, mode: int) -> None:
    atomic_replace(path, text.encode("utf-8"), mode)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _relative_name(path: Path, root: Path) -> str:
    if path == root:
        return "."
    return path.relative_to(root).as_posix()


def _kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "unknown"


def _hash_file_nofollow(path: Path) -> tuple[str, os.stat_result]:
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeInputError(f"not a regular file while hashing: {path}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise IntegrityError(f"file changed before it could be opened safely: {path}")
        while True:
            chunk = os.read(fd, _CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        after_fd = os.fstat(fd)
    finally:
        os.close(fd)
    after_path = path.lstat()
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(opened, field) != getattr(after_fd, field) for field in stable_fields):
        raise IntegrityError(f"file changed while it was being read: {path}")
    if any(getattr(after_fd, field) != getattr(after_path, field) for field in stable_fields):
        raise IntegrityError(f"file was replaced while it was being read: {path}")
    return digest.hexdigest(), after_path


def _read_file_nofollow(path: Path, limit: int) -> tuple[bytes, bool]:
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    chunks: list[bytes] = []
    remaining = limit + 1
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeInputError(f"not a regular file while inspecting: {path}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise IntegrityError(f"file changed before inspection: {path}")
        while remaining:
            chunk = os.read(fd, min(_CHUNK_SIZE, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after_fd = os.fstat(fd)
    finally:
        os.close(fd)
    after_path = path.lstat()
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(opened, field) != getattr(after_fd, field) for field in stable_fields):
        raise IntegrityError(f"file changed during inspection: {path}")
    if any(getattr(after_fd, field) != getattr(after_path, field) for field in stable_fields):
        raise IntegrityError(f"file was replaced during inspection: {path}")
    data = b"".join(chunks)
    return data[:limit], len(data) <= limit and after_fd.st_size <= limit


def _snapshot_file_nofollow(
    path: Path,
    destination: Path,
    *,
    inspect_limit: int,
    snapshot_limit: int,
) -> tuple[str, os.stat_result, bytes, bool]:
    """hash, inspect and snapshot exactly one stable opened inode."""
    before_path = path.lstat()
    source_fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    output_fd = -1
    digest = hashlib.sha256()
    sample = bytearray()
    try:
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeInputError(f"not a regular file while snapshotting: {path}")
        if (opened.st_dev, opened.st_ino) != (before_path.st_dev, before_path.st_ino):
            raise IntegrityError(f"file changed before snapshot: {path}")
        if opened.st_size > snapshot_limit:
            raise IntegrityError(f"file exceeds the bounded immutable-snapshot limit ({snapshot_limit} bytes): {path}")
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        output_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        os.fchmod(output_fd, 0o400)
        total = 0
        while chunk := os.read(source_fd, _CHUNK_SIZE):
            total += len(chunk)
            if total > snapshot_limit:
                raise IntegrityError(f"file grew beyond the immutable-snapshot limit: {path}")
            digest.update(chunk)
            if len(sample) <= inspect_limit:
                sample.extend(chunk[: inspect_limit + 1 - len(sample)])
            view = memoryview(chunk)
            while view:
                view = view[os.write(output_fd, view) :]
        os.fsync(output_fd)
        after_fd = os.fstat(source_fd)
        after_path = path.lstat()
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(opened, name) != getattr(after_fd, name) for name in stable_fields):
            raise IntegrityError(f"file changed while it was snapshotted: {path}")
        if any(getattr(after_fd, name) != getattr(after_path, name) for name in stable_fields):
            raise IntegrityError(f"file was replaced while it was snapshotted: {path}")
        if total != opened.st_size:
            raise IntegrityError(f"file size changed while it was snapshotted: {path}")
        data = bytes(sample[:inspect_limit])
        complete = len(sample) <= inspect_limit and total <= inspect_limit
        return digest.hexdigest(), after_fd, data, complete
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise
    finally:
        os.close(source_fd)
        if output_fd >= 0:
            os.close(output_fd)


_SNAPSHOT_FILE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_SNAPSHOT_DIRECTORY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _stat_fields_equal(
    first: os.stat_result,
    second: os.stat_result,
    fields: Sequence[str],
) -> bool:
    return all(getattr(first, field) == getattr(second, field) for field in fields)


def _snapshot_open_regular(
    source_fd: int,
    before_entry: os.stat_result,
    destination: Path,
    *,
    source_label: str,
    max_bytes: int | None,
    mode: int,
) -> tuple[str, os.stat_result, int]:
    """copy and hash exactly one already-opened stable regular inode."""

    if max_bytes is not None and max_bytes < 0:
        raise IntegrityError(f"private snapshot budget exhausted before: {source_label}")
    if mode not in (0o400, 0o500):
        raise ValueError("private scanner snapshots must use mode 0400 or 0500")
    opened = os.fstat(source_fd)
    if not stat.S_ISREG(opened.st_mode):
        raise UnsafeInputError(f"trusted material is not a regular file: {source_label}")
    if not _stat_fields_equal(before_entry, opened, _SNAPSHOT_FILE_FIELDS):
        raise IntegrityError(f"trusted material changed before capture: {source_label}")
    if max_bytes is not None and opened.st_size > max_bytes:
        raise IntegrityError(f"trusted material exceeds its private snapshot limit: {source_label}")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_fd = -1
    destination_created = False
    digest = hashlib.sha256()
    total = 0
    try:
        output_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        destination_created = True
        os.fchmod(output_fd, mode)
        while chunk := os.read(source_fd, _CHUNK_SIZE):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise IntegrityError(f"trusted material grew beyond its private snapshot limit: {source_label}")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(output_fd, view) :]
        os.fsync(output_fd)
        after_fd = os.fstat(source_fd)
        if not _stat_fields_equal(opened, after_fd, _SNAPSHOT_FILE_FIELDS) or total != opened.st_size:
            raise IntegrityError(f"trusted material changed during capture: {source_label}")
        captured = os.fstat(output_fd)
        if (
            not stat.S_ISREG(captured.st_mode)
            or stat.S_IMODE(captured.st_mode) != mode
            or captured.st_nlink != 1
            or captured.st_size != total
        ):
            raise IntegrityError(f"private scanner snapshot is unsafe: {destination}")
        return digest.hexdigest(), after_fd, total
    except BaseException:
        if destination_created:
            with contextlib.suppress(FileNotFoundError):
                destination.unlink()
        raise
    finally:
        if output_fd >= 0:
            os.close(output_fd)


def _snapshot_regular_path(
    source: Path,
    destination: Path,
    *,
    max_bytes: int | None,
    mode: int,
) -> tuple[str, os.stat_result, int]:
    source = source.expanduser().absolute()
    before = source.lstat()
    source_fd = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    captured_destination = False
    try:
        digest, captured, total = _snapshot_open_regular(
            source_fd,
            before,
            destination,
            source_label=str(source),
            max_bytes=max_bytes,
            mode=mode,
        )
        captured_destination = True
        after = source.lstat()
        if not _stat_fields_equal(captured, after, _SNAPSHOT_FILE_FIELDS):
            raise IntegrityError(f"trusted material was replaced during capture: {source}")
        return digest, captured, total
    except BaseException:
        if captured_destination:
            with contextlib.suppress(FileNotFoundError):
                destination.unlink()
        raise
    finally:
        os.close(source_fd)


def _snapshot_directory_tree(
    source: Path,
    destination: Path,
    *,
    max_files: int | None,
    max_file_bytes: int | None,
    max_total_bytes: int | None,
) -> tuple[str, int]:
    """capture a symlink-free tree through held directory fds and hash its source metadata."""

    source = source.expanduser().absolute()
    if os.path.lexists(destination):
        raise IntegrityError(f"private trust snapshot destination already exists: {destination}")
    before_root = source.lstat()
    if not stat.S_ISDIR(before_root.st_mode):
        raise UnsafeInputError(f"trusted material is not a directory: {source}")
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    root_fd = os.open(source, directory_flags)
    entries: list[dict[str, object]] = []
    counters = {"files": 0, "bytes": 0}
    destination_created = False
    try:
        opened_root = os.fstat(root_fd)
        if not _stat_fields_equal(before_root, opened_root, _SNAPSHOT_DIRECTORY_FIELDS):
            raise IntegrityError(f"trusted directory changed before capture: {source}")
        destination.mkdir(mode=0o700)
        destination_created = True
        os.chmod(destination, 0o700)

        def capture_directory(
            directory_fd: int,
            target: Path,
            relative: PurePosixPath,
            depth: int,
        ) -> None:
            if depth > _MAX_TRUST_TREE_DEPTH:
                raise UnsafeInputError("trusted material tree exceeds its safe depth limit")
            before_directory = os.fstat(directory_fd)
            names_before = sorted(os.listdir(directory_fd), key=os.fsencode)
            for name in names_before:
                counters["files"] += 1
                if max_files is not None and counters["files"] > max_files:
                    raise IntegrityError("trusted material tree exceeds its private file-count limit")
                before_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                relative_entry = relative / name
                relative_text = relative_entry.as_posix()
                target_entry = target / name
                if stat.S_ISDIR(before_entry.st_mode):
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                    try:
                        opened_child = os.fstat(child_fd)
                        if not _stat_fields_equal(before_entry, opened_child, _SNAPSHOT_DIRECTORY_FIELDS):
                            raise IntegrityError(f"trusted directory changed before capture: {source / relative_text}")
                        if opened_child.st_dev != opened_root.st_dev:
                            raise UnsafeInputError(
                                f"trusted material crosses a filesystem boundary: {source / relative_text}"
                            )
                        target_entry.mkdir(mode=0o700)
                        os.chmod(target_entry, 0o700)
                        entries.append(
                            {
                                "path": relative_text,
                                "kind": "directory",
                                "mode": stat.S_IMODE(opened_child.st_mode),
                            }
                        )
                        capture_directory(child_fd, target_entry, relative_entry, depth + 1)
                        after_child_fd = os.fstat(child_fd)
                        after_child_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if not _stat_fields_equal(
                            opened_child, after_child_fd, _SNAPSHOT_DIRECTORY_FIELDS
                        ) or not _stat_fields_equal(after_child_fd, after_child_entry, _SNAPSHOT_DIRECTORY_FIELDS):
                            raise IntegrityError(f"trusted directory changed during capture: {source / relative_text}")
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(before_entry.st_mode):
                    remaining = None if max_total_bytes is None else max_total_bytes - counters["bytes"]
                    per_file_limit = max_file_bytes
                    if remaining is not None:
                        per_file_limit = remaining if per_file_limit is None else min(per_file_limit, remaining)
                    file_fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory_fd,
                    )
                    try:
                        digest, captured, total = _snapshot_open_regular(
                            file_fd,
                            before_entry,
                            target_entry,
                            source_label=str(source / relative_text),
                            max_bytes=per_file_limit,
                            mode=0o400,
                        )
                        after_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if not _stat_fields_equal(captured, after_entry, _SNAPSHOT_FILE_FIELDS):
                            raise IntegrityError(
                                f"trusted material was replaced during capture: {source / relative_text}"
                            )
                    finally:
                        os.close(file_fd)
                    counters["bytes"] += total
                    entries.append({"path": relative_text, "kind": "regular", "sha256": digest})
                else:
                    raise UnsafeInputError(
                        f"trusted material contains a link or special file: {source / relative_text}"
                    )
            names_after = sorted(os.listdir(directory_fd), key=os.fsencode)
            after_directory = os.fstat(directory_fd)
            if names_before != names_after or not _stat_fields_equal(
                before_directory, after_directory, _SNAPSHOT_DIRECTORY_FIELDS
            ):
                raise IntegrityError(f"trusted directory changed during capture: {source / relative}")

        capture_directory(root_fd, destination, PurePosixPath(), 0)
        after_root_fd = os.fstat(root_fd)
        after_root_path = source.lstat()
        if not _stat_fields_equal(opened_root, after_root_fd, _SNAPSHOT_DIRECTORY_FIELDS) or not _stat_fields_equal(
            after_root_fd, after_root_path, _SNAPSHOT_DIRECTORY_FIELDS
        ):
            raise IntegrityError(f"trusted directory was replaced during capture: {source}")
        entries.sort(key=lambda entry: os.fsencode(str(entry["path"])))
        return _canonical_json_hash(entries), counters["bytes"]
    except BaseException:
        if destination_created and destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        os.close(root_fd)


def _snapshot_path_or_tree(
    source: Path,
    destination: Path,
    *,
    max_files: int | None,
    max_file_bytes: int | None,
    max_total_bytes: int | None,
) -> tuple[str, bool, int]:
    source = source.expanduser().absolute()
    info = source.lstat()
    if stat.S_ISREG(info.st_mode):
        limit = max_file_bytes
        if max_total_bytes is not None:
            limit = max_total_bytes if limit is None else min(limit, max_total_bytes)
        digest, _captured, total = _snapshot_regular_path(
            source,
            destination,
            max_bytes=limit,
            mode=0o400,
        )
        return digest, False, total
    if stat.S_ISDIR(info.st_mode):
        digest, total = _snapshot_directory_tree(
            source,
            destination,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        return digest, True, total
    raise UnsafeInputError(f"trusted material must be a regular file or directory: {source}")


def _hash_path_or_tree(path: Path) -> str:
    """compute the versioned trust hash from a stable private capture."""

    with tempfile.TemporaryDirectory(prefix="umzug-trust-hash-") as temp_name:
        root = Path(temp_name)
        os.chmod(root, 0o700)
        digest, _is_directory, _total = _snapshot_path_or_tree(
            path,
            root / "material",
            max_files=None,
            max_file_bytes=None,
            max_total_bytes=None,
        )
        return digest


def _safe_display_output(output: bytes, root: Path, limit: int) -> str:
    clipped = output[:limit].decode("utf-8", "backslashreplace")
    return clipped.replace(str(root), "<ROOT>").strip()


class ZeroTrustScanner:
    """inspect filesystem objects without executing or extracting them."""

    def __init__(self, policy: ScanPolicy | None = None) -> None:
        self.policy = policy or ScanPolicy()

    def scan(self, root: Path | str, stage: Stage = Stage.QUARANTINE) -> ScanReport:
        root = Path(root).absolute()
        if not root.exists() and not root.is_symlink():
            raise FileNotFoundError(root)

        findings: list[Finding] = []
        records: list[FileRecord] = []
        regular_paths: list[tuple[Path, str]] = []
        snapshot_hashes: dict[str, str] = {}
        snapshot_context = tempfile.TemporaryDirectory(prefix="umzug-scan-snapshot-")
        snapshot_root = Path(snapshot_context.name)
        os.chmod(snapshot_root, 0o700)
        trust_context = tempfile.TemporaryDirectory(prefix="umzug-scanner-trust-")
        trust_root = Path(trust_context.name)
        os.chmod(trust_root, 0o700)
        snapshot_bytes = 0
        inode_paths: dict[tuple[int, int], list[str]] = defaultdict(list)
        inode_link_counts: dict[tuple[int, int], int] = {}
        archive_budget = _ArchiveBudget()

        tool_evidence, tool_snapshots = self._discover_tools(findings, trust_root / "tools")
        trust = _ScannerTrustSnapshots(
            tools=tool_snapshots,
            yara_rules=self._capture_material_set(
                self.policy.yara_rule_paths,
                self.policy.trusted_yara_rule_hashes,
                trust_root / "materials",
                "yara",
            ),
            clam_signatures=self._capture_material_set(
                self.policy.clam_signature_paths,
                self.policy.trusted_clam_signature_hashes,
                trust_root / "materials",
                "clam",
            ),
        )
        self._check_external_material(findings, tool_evidence, trust)
        if stage is Stage.SOURCE:
            if self.policy.require_secure_source_mount:
                self._inspect_source_mount(root, findings)
            else:
                findings.append(
                    _finding(
                        Severity.INFO,
                        "source_mount_policy_relaxed",
                        ".",
                        "SOURCE mount enforcement was explicitly disabled; an upstream attestation must justify this derived staging transition.",
                    )
                )
        if not self.policy.strict_external:
            findings.append(
                _finding(
                    Severity.INFO,
                    "external_policy_relaxed",
                    ".",
                    "Strict external-scanner enforcement was explicitly disabled.",
                )
            )

        paths = self._walk_nofollow(root, findings)
        if len(paths) > self.policy.max_files:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "file_count_limit",
                    ".",
                    "The candidate exceeds the configured file-count limit and was not fully inspected.",
                    observed=len(paths),
                    limit=self.policy.max_files,
                )
            )
            paths = paths[: self.policy.max_files]

        for path in paths:
            rel = _relative_name(path, root)
            try:
                info = path.lstat()
            except OSError as exc:
                findings.append(
                    _finding(Severity.BLOCKER, "lstat_failed", rel, "Metadata could not be read.", error=str(exc))
                )
                continue

            self._inspect_name(rel, findings)
            kind = _kind(info.st_mode)
            record = FileRecord(
                path=rel,
                kind=kind,
                size=info.st_size,
                mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid,
                gid=info.st_gid,
                mtime_ns=info.st_mtime_ns,
                nlink=info.st_nlink,
            )

            if kind == "regular":
                try:
                    read_limit = (
                        self.policy.max_archive_input_bytes
                        if path.suffix.lower() in _ARCHIVE_EXTENSIONS
                        else self.policy.max_inspect_bytes
                    )
                    snapshot_relative = Path("__candidate_root_file__") if rel == "." else Path(rel)
                    snapshot_path = snapshot_root / snapshot_relative
                    remaining_snapshot_bytes = self.policy.max_archive_expanded_bytes - snapshot_bytes
                    digest, stable_info, data, complete = _snapshot_file_nofollow(
                        path,
                        snapshot_path,
                        inspect_limit=read_limit,
                        snapshot_limit=min(
                            self.policy.max_archive_input_bytes,
                            max(0, remaining_snapshot_bytes),
                        ),
                    )
                    snapshot_bytes += stable_info.st_size
                    detected = self._detect_type(data, path.name)
                    record = dataclasses.replace(
                        record,
                        size=stable_info.st_size,
                        mode=stat.S_IMODE(stable_info.st_mode),
                        uid=stable_info.st_uid,
                        gid=stable_info.st_gid,
                        mtime_ns=stable_info.st_mtime_ns,
                        nlink=stable_info.st_nlink,
                        sha256=digest,
                        detected_type=detected,
                    )
                    inode_key = (stable_info.st_dev, stable_info.st_ino)
                    inode_paths[inode_key].append(rel)
                    inode_link_counts[inode_key] = stable_info.st_nlink
                    self._inspect_mode(record, findings)
                    self._inspect_xattrs(path, rel, findings)
                    self._inspect_regular_content(
                        data,
                        complete,
                        rel,
                        path.name,
                        detected,
                        findings,
                        archive_budget,
                        depth=0,
                    )
                    regular_paths.append((snapshot_path, rel))
                    snapshot_hashes[rel] = digest
                except (OSError, ScannerError) as exc:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "file_inspection_failed",
                            rel,
                            "The file could not be read completely and safely.",
                            error=str(exc),
                        )
                    )
            elif kind == "directory":
                self._inspect_mode(record, findings)
                self._inspect_xattrs(path, rel, findings)
            elif kind == "symlink":
                try:
                    target = os.readlink(path)
                    record = dataclasses.replace(record, link_target=target)
                    if rel == ".":
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "symlink_root",
                                rel,
                                "A candidate root may not itself be a symbolic link.",
                                target=target,
                            )
                        )
                    self._inspect_symlink(path, target, root, rel, findings)
                    self._inspect_xattrs(path, rel, findings)
                except OSError as exc:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "symlink_read_failed",
                            rel,
                            "The symbolic link could not be inspected.",
                            error=str(exc),
                        )
                    )
            else:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "special_file",
                        rel,
                        "Device nodes, sockets, FIFOs, and unknown filesystem objects cannot be approved.",
                        kind=kind,
                    )
                )
            records.append(record)

        records = self._annotate_and_check_hardlinks(records, inode_paths, inode_link_counts, findings)
        detected_types = {record.path: record.detected_type for record in records}
        try:
            external_results = self._run_external_scanners(
                snapshot_root,
                regular_paths,
                tool_evidence,
                findings,
                detected_types,
                trust,
            )
            for snapshot_path, rel in regular_paths:
                observed = _hash_file_nofollow(snapshot_path)[0]
                if not hmac.compare_digest(observed, snapshot_hashes[rel]):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "analysis_snapshot_changed",
                            rel,
                            "The immutable external-analysis snapshot changed during scanning.",
                        )
                    )
        finally:
            snapshot_context.cleanup()
            trust_context.cleanup()
        records.sort(key=lambda record: os.fsencode(record.path))
        manifest = _manifest_hash(records)
        try:
            current_manifest = self.current_manifest_sha256(root)
            if not hmac.compare_digest(current_manifest, manifest):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "candidate_changed_during_scan",
                        ".",
                        "The candidate no longer matches the exact bytes analyzed from immutable snapshots.",
                        expected_manifest=manifest,
                        observed_manifest=current_manifest,
                    )
                )
        except (OSError, ScannerError) as exc:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "candidate_recheck_failed",
                    ".",
                    "The candidate could not be revalidated after analysis.",
                    error=str(exc),
                )
            )
        findings.sort(key=lambda finding: (finding.path, finding.rule, finding.id))
        scan_id = hashlib.sha256(f"{manifest}\0{stage.value}\0{_now()}\0{os.getpid()}".encode("utf-8")).hexdigest()[:32]
        return ScanReport(
            schema_version=SCHEMA_VERSION,
            scan_id=scan_id,
            scanned_at=_now(),
            root=str(root),
            stage=stage,
            policy=self._policy_for_report(),
            records=tuple(records),
            findings=tuple(findings),
            manifest_sha256=manifest,
            tools=tool_evidence,
            external_results=tuple(external_results),
        )

    def current_manifest_sha256(self, root: Path | str) -> str:
        """recompute the binding manifest without claiming a new analysis."""

        root = Path(root).absolute()
        findings: list[Finding] = []
        paths = self._walk_nofollow(root, findings)
        if findings:
            raise IntegrityError("the candidate tree cannot be enumerated safely")
        records: list[FileRecord] = []
        inode_paths: dict[tuple[int, int], list[str]] = defaultdict(list)
        inode_counts: dict[tuple[int, int], int] = {}
        for path in paths:
            info = path.lstat()
            rel = _relative_name(path, root)
            kind = _kind(info.st_mode)
            sha256: str | None = None
            target: str | None = None
            if kind == "regular":
                sha256, info = _hash_file_nofollow(path)
                key = (info.st_dev, info.st_ino)
                inode_paths[key].append(rel)
                inode_counts[key] = info.st_nlink
            elif kind == "symlink":
                target = os.readlink(path)
            records.append(
                FileRecord(
                    path=rel,
                    kind=kind,
                    size=info.st_size,
                    mode=stat.S_IMODE(info.st_mode),
                    uid=info.st_uid,
                    gid=info.st_gid,
                    mtime_ns=info.st_mtime_ns,
                    nlink=info.st_nlink,
                    sha256=sha256,
                    link_target=target,
                )
            )
        records = self._annotate_hardlinks(records, inode_paths)
        records.sort(key=lambda record: os.fsencode(record.path))
        return _manifest_hash(records)

    def validate_source_mount(self, root: Path | str) -> tuple[Finding, ...]:
        """preflight SOURCE mount flags without enumerating candidate content."""

        findings: list[Finding] = []
        self._inspect_source_mount(Path(root).absolute(), findings)
        return tuple(findings)

    def assert_unchanged(self, report: ScanReport) -> None:
        current = self.current_manifest_sha256(Path(report.root))
        if current != report.manifest_sha256:
            raise IntegrityError(f"candidate changed after scan: expected {report.manifest_sha256}, got {current}")

    def _policy_for_report(self) -> dict[str, object]:
        policy = dataclasses.asdict(self.policy)
        # paths are represented portably; trusted hashes are not secrets.
        policy["yara_rule_paths"] = [str(path) for path in self.policy.yara_rule_paths]
        policy["clam_signature_paths"] = [str(path) for path in self.policy.clam_signature_paths]
        return policy

    def _walk_nofollow(self, root: Path, findings: list[Finding]) -> list[Path]:
        """enumerate through held directory descriptors and reject tree drift."""

        result: list[Path] = []
        try:
            root_parent_fd, root_name = _open_existing_parent_nofollow(root)
            try:
                root_info = os.stat(
                    root_name,
                    dir_fd=root_parent_fd,
                    follow_symlinks=False,
                )
                root_fd: int | None = None
                if stat.S_ISDIR(root_info.st_mode):
                    root_fd = os.open(
                        root_name,
                        _directory_open_flags(),
                        dir_fd=root_parent_fd,
                    )
                    opened = os.fstat(root_fd)
                    if not _same_inode_and_type(root_info, opened):
                        os.close(root_fd)
                        raise IntegrityError("candidate root changed while opening it")
                    root_info = opened
            finally:
                os.close(root_parent_fd)
        except (OSError, ScannerError) as exc:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "directory_enumeration_failed",
                    ".",
                    "The candidate root could not be opened without following symlinks.",
                    error=str(exc),
                )
            )
            return result

        root_device = root_info.st_dev
        stack: list[tuple[Path, os.stat_result, int | None]] = [(root, root_info, root_fd)]
        try:
            while stack:
                path, info, directory_fd = stack.pop()
                result.append(path)
                children: list[tuple[Path, os.stat_result, int | None]] = []
                try:
                    if path != root and info.st_dev != root_device and not self.policy.allow_cross_filesystems:
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "cross_filesystem_boundary",
                                _relative_name(path, root),
                                "A nested mount/filesystem boundary was not traversed under fail-closed policy.",
                                root_device=root_device,
                                observed_device=info.st_dev,
                            )
                        )
                        continue
                    if not stat.S_ISDIR(info.st_mode):
                        continue
                    if directory_fd is None:
                        raise IntegrityError("directory entry has no anchored descriptor")
                    before = os.fstat(directory_fd)
                    names_before = sorted(os.listdir(directory_fd), key=os.fsencode)
                    for name in names_before:
                        if name in {"", ".", ".."} or "/" in name or "\x00" in name:
                            raise IntegrityError("directory enumeration returned an unsafe entry name")
                        if len(result) + len(stack) + len(children) >= self.policy.max_files:
                            findings.append(
                                _finding(
                                    Severity.BLOCKER,
                                    "file_count_limit",
                                    _relative_name(path, root),
                                    "The candidate exceeds the configured file-count limit and was not fully enumerated.",
                                    observed_at_least=self.policy.max_files + 1,
                                    limit=self.policy.max_files,
                                )
                            )
                            return result
                        child_info = os.stat(
                            name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                        child_fd: int | None = None
                        if stat.S_ISDIR(child_info.st_mode):
                            child_fd = os.open(
                                name,
                                _directory_open_flags(),
                                dir_fd=directory_fd,
                            )
                            opened = os.fstat(child_fd)
                            if not _same_inode_and_type(child_info, opened):
                                os.close(child_fd)
                                raise IntegrityError(f"directory entry changed while opening it: {name}")
                            child_info = opened
                        children.append((path / name, child_info, child_fd))
                    names_after = sorted(os.listdir(directory_fd), key=os.fsencode)
                    after = os.fstat(directory_fd)
                    if names_before != names_after or _stable_source_stat(before) != _stable_source_stat(after):
                        raise IntegrityError("directory changed while it was being enumerated")
                    children.sort(
                        key=lambda child: os.fsencode(child[0].name),
                        reverse=True,
                    )
                    stack.extend(children)
                    children = []
                except (OSError, ScannerError) as exc:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "directory_enumeration_failed",
                            _relative_name(path, root),
                            "A directory could not be enumerated completely.",
                            error=str(exc),
                        )
                    )
                finally:
                    for _, _, child_fd in children:
                        if child_fd is not None:
                            os.close(child_fd)
                    if directory_fd is not None:
                        os.close(directory_fd)
        finally:
            for _, _, directory_fd in stack:
                if directory_fd is not None:
                    os.close(directory_fd)
        return result

    def _inspect_source_mount(self, root: Path, findings: list[Finding]) -> None:
        """require SOURCE to reside on the deepest matching hardened mount."""

        try:
            lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
            candidate = root.resolve(strict=False)
            matches: list[tuple[Path, set[str]]] = []
            for line in lines:
                fields = line.split()
                separator = fields.index("-")
                mountpoint = Path(_decode_mountinfo_path(fields[4]))
                try:
                    candidate.relative_to(mountpoint)
                except ValueError:
                    continue
                options = set(fields[5].split(","))
                if len(fields) > separator + 3:
                    options.update(fields[separator + 3].split(","))
                matches.append((mountpoint, options))
            if not matches:
                raise ValueError("no containing mount entry")
            mountpoint, options = max(matches, key=lambda item: len(item[0].parts))
        except (OSError, ValueError, IndexError) as exc:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "source_mount_unknown",
                    ".",
                    "SOURCE mount properties could not be established.",
                    error=str(exc),
                )
            )
            return
        missing = sorted(set(self.policy.required_source_mount_options) - options)
        if missing:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "source_mount_insecure",
                    ".",
                    "SOURCE must be mounted read-only with noexec, nodev, and nosuid before intake.",
                    mountpoint=str(mountpoint),
                    missing_options=missing,
                    observed_options=sorted(options),
                )
            )

    def _inspect_name(self, relative: str, findings: list[Finding]) -> None:
        if relative == ".":
            return
        for component in PurePosixPath(relative).parts:
            if component in {".", ".."}:
                findings.append(
                    _finding(
                        Severity.BLOCKER, "unsafe_path_component", relative, "The path contains a traversal component."
                    )
                )
            if component.startswith("."):
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "hidden_name",
                        relative,
                        "A hidden file or directory requires explicit review.",
                        component=component,
                    )
                )
            if ":" in component:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "alternate_stream_name",
                        relative,
                        "A colon in a filename can represent an alternate data stream on other filesystems.",
                        component=component,
                    )
                )
            problematic = []
            scripts: set[str] = set()
            for char in component:
                category = unicodedata.category(char)
                if category in {"Cf", "Cc", "Cs"} or char in {"\u00ad", "\u034f", "\u061c"}:
                    problematic.append(f"U+{ord(char):04X}")
                name = unicodedata.name(char, "")
                for script in ("LATIN", "CYRILLIC", "GREEK"):
                    if script in name and char.isalpha():
                        scripts.add(script)
            if problematic:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "invisible_or_control_name",
                        relative,
                        "The filename contains invisible, control, bidi, or undecodable characters.",
                        codepoints=problematic,
                    )
                )
            if len(scripts) > 1:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "mixed_script_name",
                        relative,
                        "The filename mixes scripts and may contain homoglyphs.",
                        scripts=sorted(scripts),
                    )
                )
            normalized = unicodedata.normalize("NFKC", component)
            if normalized != component:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "compatibility_normalized_name",
                        relative,
                        "The filename changes under Unicode compatibility normalization.",
                        normalized=normalized,
                    )
                )

    def _inspect_mode(self, record: FileRecord, findings: list[Finding]) -> None:
        if record.mode & (stat.S_ISUID | stat.S_ISGID):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "privileged_mode",
                    record.path,
                    "SUID and SGID mode bits are forbidden in migration candidates.",
                    mode=oct(record.mode),
                )
            )
        if record.mode & 0o022:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "group_or_world_writable",
                    record.path,
                    "Group/world-writable migration objects are forbidden until permissions are normalized.",
                    mode=oct(record.mode),
                )
            )
        if record.kind == "regular" and record.mode & 0o111:
            severity = Severity.REVIEW if self.policy.allow_executable_files_after_review else Severity.BLOCKER
            findings.append(
                _finding(
                    severity,
                    "executable_mode",
                    record.path,
                    "An executable mode bit requires removal or explicit policy review.",
                    mode=oct(record.mode),
                )
            )

    def _inspect_xattrs(self, path: Path, rel: str, findings: list[Finding]) -> None:
        try:
            names = os.listxattr(path, follow_symlinks=False)
        except OSError as exc:
            if exc.errno in {errno.ENOTSUP, getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)}:
                return
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "xattr_enumeration_failed",
                    rel,
                    "Extended attributes could not be enumerated.",
                    error=str(exc),
                )
            )
            return
        for name in sorted(names):
            try:
                value = os.getxattr(path, name, follow_symlinks=False)
                value_hash = hashlib.sha256(value).hexdigest()
            except OSError as exc:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "xattr_read_failed",
                        rel,
                        "An extended attribute could not be read.",
                        name=name,
                        error=str(exc),
                    )
                )
                continue
            if name == "security.capability":
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "linux_capability",
                        rel,
                        "Linux file capabilities are forbidden until deliberately recreated on the target.",
                        name=name,
                        value_sha256=value_hash,
                    )
                )
            elif "posix_acl" in name:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "filesystem_acl",
                        rel,
                        "An ACL requires explicit identity and permission review.",
                        name=name,
                        value_sha256=value_hash,
                    )
                )
            else:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "extended_attribute",
                        rel,
                        "An extended attribute requires explicit review and is not implicitly trusted.",
                        name=name,
                        value_sha256=value_hash,
                    )
                )

    def _inspect_symlink(self, path: Path, target: str, root: Path, rel: str, findings: list[Finding]) -> None:
        if "\x00" in target or _unsafe_archive_path(target):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "unsafe_symlink_target",
                    rel,
                    "The symbolic-link target is absolute or contains traversal.",
                    target=target,
                )
            )
            return
        try:
            resolved_root = root.resolve(strict=False)
            resolved_target = (path.parent / target).resolve(strict=False)
            if not _is_relative_to(resolved_target, resolved_root):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "symlink_escape",
                        rel,
                        "The symbolic link resolves outside the candidate root.",
                        target=target,
                    )
                )
        except (OSError, RuntimeError) as exc:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "symlink_resolution_failed",
                    rel,
                    "The symbolic-link target could not be resolved safely.",
                    target=target,
                    error=str(exc),
                )
            )

    def _annotate_hardlinks(
        self,
        records: list[FileRecord],
        inode_paths: Mapping[tuple[int, int], list[str]],
    ) -> list[FileRecord]:
        groups: dict[str, str] = {}
        for paths in inode_paths.values():
            if len(paths) > 1:
                group = hashlib.sha256("\0".join(sorted(paths)).encode("utf-8", "surrogateescape")).hexdigest()[:16]
                for path in paths:
                    groups[path] = group
        return [dataclasses.replace(record, hardlink_group=groups.get(record.path)) for record in records]

    def _annotate_and_check_hardlinks(
        self,
        records: list[FileRecord],
        inode_paths: Mapping[tuple[int, int], list[str]],
        inode_link_counts: Mapping[tuple[int, int], int],
        findings: list[Finding],
    ) -> list[FileRecord]:
        for inode, paths in inode_paths.items():
            if inode_link_counts.get(inode, 1) > len(paths):
                for path in paths:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "hardlink_escape",
                            path,
                            "The inode has hard links outside the scanned candidate.",
                            observed_links=inode_link_counts[inode],
                            links_inside_candidate=len(paths),
                        )
                    )
        return self._annotate_hardlinks(records, inode_paths)

    def _detect_type(self, data: bytes, filename: str) -> str:
        if data.startswith(b"\x7fELF"):
            return "elf"
        if data.startswith(b"MZ"):
            return "pe"
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
            return "zip"
        if data.startswith(b"\x1f\x8b"):
            return "gzip"
        if data.startswith(b"BZh"):
            return "bzip2"
        if data.startswith(b"\xfd7zXZ\x00"):
            return "xz"
        if data.startswith(b"7z\xbc\xaf'\x1c"):
            return "7zip"
        if data.startswith(b"Rar!\x1a\x07"):
            return "rar"
        if data.startswith(b"!<arch>\n"):
            return "deb" if filename.lower().endswith(".deb") else "ar"
        if data.startswith(b"\xed\xab\xee\xdb"):
            return "rpm"
        if data.startswith(b"\x28\xb5\x2f\xfd"):
            return "zstd"
        if data.startswith(b"%PDF-"):
            return "pdf"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if data.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if data.startswith((b"GIF87a", b"GIF89a")):
            return "gif"
        if data.startswith(b"OggS"):
            return "ogg"
        if data.startswith(b"ID3"):
            return "mp3"
        if data.startswith(b"#!"):
            return "script"
        if len(data) >= 262 and data[257:262] == b"ustar":
            return "tar"
        if data and b"\x00" not in data[:8192]:
            try:
                data[:8192].decode("utf-8")
                return "text"
            except UnicodeDecodeError:
                pass
        if not data:
            return "empty"
        return "binary"

    def _inspect_regular_content(
        self,
        data: bytes,
        complete: bool,
        rel: str,
        filename: str,
        detected: str,
        findings: list[Finding],
        budget: _ArchiveBudget,
        depth: int,
        package_context: bool = False,
    ) -> None:
        suffix = Path(filename).suffix.lower()
        if not complete:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "inspection_size_limit",
                    rel,
                    "The file exceeds the inspection limit and was not analyzed completely.",
                    inspected_bytes=len(data),
                )
            )
            return

        if detected in {"elf", "pe"}:
            if package_context:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "packaged_native_executable",
                        rel,
                        "A native executable inside a distribution package requires the separately hash-bound vendor-signature decision.",
                        detected_type=detected,
                    )
                )
            else:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "native_executable",
                        rel,
                        "Native ELF/PE content is never implicitly approved.",
                        detected_type=detected,
                    )
                )
        elif detected == "script":
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "script_content",
                    rel,
                    "A script requires source review even when its executable bit is absent.",
                )
            )
        elif detected == "text" and suffix in _EXECUTABLE_EXTENSIONS:
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "script_source_review",
                    rel,
                    "Source with a script-language extension requires explicit review even without a shebang or executable bit.",
                    suffix=suffix,
                )
            )
        elif detected == "binary" and self.policy.block_all_unknown_binary:
            severity = Severity.REVIEW if package_context else Severity.BLOCKER
            rule = "packaged_binary_review" if package_context else "unknown_binary"
            findings.append(
                _finding(
                    severity, rule, rel, "Unknown binary content cannot be fully interpreted by the built-in inspector."
                )
            )

        if suffix in _EXECUTABLE_EXTENSIONS and detected not in {"elf", "pe", "script", "text"}:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "executable_type_mismatch",
                    rel,
                    "An executable-looking filename contains an unexpected content type.",
                    suffix=suffix,
                    detected_type=detected,
                )
            )
        if suffix in _ARCHIVE_EXTENSIONS and detected not in {
            "zip",
            "gzip",
            "bzip2",
            "xz",
            "tar",
            "7zip",
            "rar",
            "deb",
            "rpm",
            "ar",
            "zstd",
        }:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_type_mismatch",
                    rel,
                    "The archive extension does not match recognizable archive content.",
                    suffix=suffix,
                    detected_type=detected,
                )
            )
        if suffix not in _ARCHIVE_EXTENSIONS and detected in {
            "zip",
            "gzip",
            "bzip2",
            "xz",
            "tar",
            "7zip",
            "rar",
            "deb",
            "rpm",
            "ar",
            "zstd",
        }:
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "hidden_archive",
                    rel,
                    "Archive content is hidden behind an unexpected filename.",
                    detected_type=detected,
                )
            )
        expected_types = {
            ".pdf": {"pdf"},
            ".png": {"png"},
            ".jpg": {"jpeg"},
            ".jpeg": {"jpeg"},
            ".gif": {"gif"},
            ".ogg": {"ogg"},
            ".mp3": {"mp3"},
        }
        if suffix in expected_types and detected not in expected_types[suffix]:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "content_type_mismatch",
                    rel,
                    "The filename type disagrees with the actual magic/content.",
                    suffix=suffix,
                    detected_type=detected,
                )
            )

        self._inspect_active_content(data, rel, suffix, detected, findings)
        self._inspect_text_and_strings(data, rel, filename, findings)
        if detected in {"deb", "ar"}:
            self._inspect_ar(data, rel, detected == "deb", findings, budget, depth)
        elif detected == "rpm":
            self._inspect_rpm(data, rel, findings, budget, depth)
        elif detected == "zstd":
            if depth >= self.policy.max_archive_depth:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_depth_limit",
                        rel,
                        "Nested zstd depth exceeds the configured limit.",
                        depth=depth,
                        limit=self.policy.max_archive_depth,
                    )
                )
                return
            try:
                expanded = self._bounded_decompress(data, "zstd")
            except (OSError, ValueError) as exc:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "zstd_decompression_unavailable",
                        rel,
                        "Zstandard content was not completely decompressed by a hash-pinned offline sandbox and cannot be approved.",
                        error=str(exc),
                    )
                )
            else:
                budget.members += 1
                budget.expanded_bytes += len(expanded)
                if self._check_archive_budget(f"{rel}!<zstd>", findings, budget):
                    ratio = len(expanded) / max(1, len(data))
                    if ratio > self.policy.max_compression_ratio:
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "archive_compression_ratio",
                                rel,
                                "The zstd stream exceeds the permitted expansion ratio.",
                                ratio=round(ratio, 3),
                                limit=self.policy.max_compression_ratio,
                            )
                        )
                    else:
                        nested_rel = f"{rel}!<zstd>"
                        nested_type = self._detect_type(expanded, "decompressed")
                        self._inspect_regular_content(
                            expanded,
                            True,
                            nested_rel,
                            "decompressed",
                            nested_type,
                            findings,
                            budget,
                            depth + 1,
                            package_context,
                        )
        if detected in {"zip", "gzip", "bzip2", "xz", "tar", "7zip", "rar"}:
            self._inspect_archive(data, rel, detected, findings, budget, depth, package_context)

    def _inspect_active_content(
        self, data: bytes, rel: str, suffix: str, detected: str, findings: list[Finding]
    ) -> None:
        lowered = data.lower()
        opaque_markers = (
            b"-----begin pgp message-----",
            b"age-encryption.org/v1",
            b"salted__",
            b"$ansible_vault;",
        )
        for marker in opaque_markers:
            if marker in lowered:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "encrypted_or_opaque_content",
                        rel,
                        "Encrypted or opaque content cannot be completely inspected.",
                        marker=marker.decode("ascii", "replace"),
                    )
                )
        if detected == "pdf":
            for marker in (
                b"/javascript",
                b"/js",
                b"/openaction",
                b"/launch",
                b"/embeddedfile",
                b"/richmedia",
                b"/encrypt",
            ):
                if marker in lowered:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "active_pdf_content",
                            rel,
                            "The PDF contains active or embedded content.",
                            marker=marker.decode("ascii"),
                        )
                    )
            eof = data.rfind(b"%%EOF")
            if eof < 0 or data[eof + 5 :].strip(b"\x00\t\r\n "):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "malformed_or_polyglot_pdf",
                        rel,
                        "The PDF lacks a clean final EOF marker or has a trailing payload.",
                    )
                )
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "complex_document_review",
                    rel,
                    "PDF semantics require isolated rendering/manual review beyond structural checks.",
                )
            )
        if re.search(rb"targetmode\s*=\s*['\"]\s*external\s*['\"]", lowered) or b"ddeauto" in lowered:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "office_external_or_dde_content",
                    rel,
                    "Office XML contains an external relationship or DDE instruction.",
                )
            )
        if any(
            marker in lowered
            for marker in (b"attachedtemplate", b"oleobject", b"vbaproject", b"externallink", b"remotetemplate")
        ):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "office_active_or_embedded_content",
                    rel,
                    "Office content contains an executable, embedded, external-link, or remote-template marker.",
                )
            )
        if suffix in {".docm", ".xlsm", ".pptm"}:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "macro_document_extension",
                    rel,
                    "Macro-enabled office documents require quarantine and manual conversion.",
                )
            )
        if suffix in {".docx", ".xlsx", ".pptx"}:
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "complex_document_review",
                    rel,
                    "Office container semantics require isolated passive conversion/manual review.",
                )
            )
        if suffix == ".rtf" and (b"\\object" in lowered or b"\\objdata" in lowered):
            findings.append(
                _finding(Severity.BLOCKER, "active_rtf_content", rel, "The RTF contains an embedded object.")
            )
        if detected in {"png", "jpeg", "gif"}:
            if b"\x7fELF" in data[16:] or b"MZ" in data[16:] or b"PK\x03\x04" in data[16:]:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "media_embedded_payload",
                        rel,
                        "The media file contains an embedded executable or archive signature.",
                    )
                )
            if detected == "png":
                error = _validate_png(data)
            elif detected == "jpeg":
                eoi = data.rfind(b"\xff\xd9")
                error = "missing JPEG end marker or trailing payload" if eoi < 0 or data[eoi + 2 :] else None
            else:
                error = "missing GIF trailer or trailing payload" if not data.endswith(b";") else None
            if error:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "malformed_media",
                        rel,
                        "The media container failed bounded structural validation.",
                        error=error,
                    )
                )
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "complex_media_review",
                    rel,
                    "Media decoder behavior requires isolated/manual review beyond structural checks.",
                )
            )
        if detected in {"ogg", "mp3"}:
            if any(marker in data[4:] for marker in (b"\x7fELF", b"MZ", b"PK\x03\x04", b"#!/")):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "media_embedded_payload",
                        rel,
                        "Audio content contains an embedded executable, archive, or script signature.",
                    )
                )
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "unsupported_media_structure",
                    rel,
                    "This MVP cannot prove complete Ogg/MP3 frame structure and therefore keeps the file in quarantine.",
                )
            )

    def _inspect_text_and_strings(self, data: bytes, rel: str, filename: str, findings: list[Finding]) -> None:
        sample = data[: self.policy.max_text_bytes]
        text = sample.decode("utf-8", "replace")
        for name, pattern in _SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "secret_material",
                        rel,
                        "Potential credentials or private key material were detected.",
                        detector=name,
                        offset=match.start(),
                    )
                )
        for name, pattern in _ENDPOINT_PATTERNS:
            matches = list(pattern.finditer(text))
            if matches:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "network_endpoint",
                        rel,
                        "Network endpoint indicators require explicit offline review.",
                        detector=name,
                        count=len(matches),
                    )
                )
        for name, pattern in _SUSPICIOUS_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "suspicious_code",
                        rel,
                        "Potential loader, persistence, network, or system-modification code was detected.",
                        detector=name,
                        offset=match.start(),
                    )
                )
        if _BASE64_BLOB.search(text) or _HEX_BLOB.search(text):
            findings.append(
                _finding(Severity.REVIEW, "obfuscated_blob", rel, "A long encoded blob may hide obfuscated content.")
            )
        if _shannon_entropy(sample) > 7.85 and len(sample) >= 4096:
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "high_entropy_content",
                    rel,
                    "High-entropy content may be encrypted, compressed, or obfuscated and requires explanation.",
                )
            )

        lower_rel = rel.lower()
        if "/.git/hooks/" in f"/{lower_rel}" or lower_rel.startswith(".git/hooks/"):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "git_hook",
                    rel,
                    "Git hooks are executable persistence points and are not migrated automatically.",
                )
            )
        for category, dangerous, indicators in _active_config_categories(rel, filename, text):
            severity = Severity.BLOCKER if dangerous else Severity.REVIEW
            rule = "active_config_execution" if dangerous else "active_config_review"
            message = (
                "An auto-loaded or command-bearing configuration is executable migration content and remains quarantined."
                if dangerous
                else "A path-activated configuration requires explicit offline review before migration."
            )
            findings.append(
                _finding(
                    severity,
                    rule,
                    rel,
                    message,
                    category=category,
                    indicators=indicators,
                )
            )
        git_config_name = filename.casefold() in {".gitconfig", "config", "config.worktree", ".gitmodules"}
        git_config_path = any(
            token in f"/{lower_rel}" for token in ("/.git/config", "/.git/config.worktree")
        ) or lower_rel.endswith("/.gitmodules")
        if git_config_name and (git_config_path or filename.casefold() in {".gitconfig", ".gitmodules"}):
            try:
                active = dangerous_git_config(
                    text,
                    repository_local=(git_config_path or filename.casefold() == ".gitmodules"),
                )
            except configparser.Error as exc:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "git_config_unparsed",
                        rel,
                        "Git configuration could not be parsed completely and remains quarantined.",
                        error=str(exc),
                    )
                )
            else:
                if active:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "git_active_config",
                            rel,
                            "Git configuration contains an include, command/helper, hook, pager, external tool, alias, submodule command, or URL rewrite.",
                            entries=active,
                        )
                    )
        if any(token in lower_rel for token in ("/boot/", "initramfs", "/lib/modules/", "/firmware/")):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "boot_kernel_firmware_path",
                    rel,
                    "Bootloader, initramfs, kernel module, or firmware material is not migrated as trusted content.",
                )
            )

    def _inspect_ar(
        self,
        data: bytes,
        rel: str,
        is_deb: bool,
        findings: list[Finding],
        budget: _ArchiveBudget,
        depth: int,
    ) -> None:
        if depth >= self.policy.max_archive_depth:
            findings.append(
                _finding(
                    Severity.BLOCKER, "archive_depth_limit", rel, "Nested ar/deb depth exceeds the configured limit."
                )
            )
            return
        if is_deb:
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "distribution_package_review",
                    rel,
                    "A structurally valid package still requires a separately verified, hash-bound vendor signature; this scanner does not assert package authenticity.",
                    package_format="deb",
                )
            )
        offset = 8
        long_names = b""
        names: list[str] = []
        while offset < len(data):
            if len(data) - offset < 60:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "ar_truncated_header",
                        rel,
                        "The ar/deb archive ends inside a member header.",
                        offset=offset,
                    )
                )
                return
            header = data[offset : offset + 60]
            if header[58:60] != b"`\n":
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "ar_invalid_header",
                        rel,
                        "An ar/deb member has an invalid header terminator.",
                        offset=offset,
                    )
                )
                return
            try:
                member_size = int(header[48:58].decode("ascii").strip())
                mode_text = header[40:48].decode("ascii").strip()
                member_mode = int(mode_text or "0", 8)
                raw_name = header[:16].decode("ascii").rstrip()
            except (UnicodeDecodeError, ValueError) as exc:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "ar_invalid_header",
                        rel,
                        "An ar/deb numeric or name field is malformed.",
                        offset=offset,
                        error=str(exc),
                    )
                )
                return
            content_start = offset + 60
            content_end = content_start + member_size
            if member_size < 0 or content_end > len(data):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "ar_truncated_member",
                        rel,
                        "An ar/deb member exceeds the archive boundary.",
                        offset=offset,
                        declared_size=member_size,
                    )
                )
                return
            member_data = data[content_start:content_end]
            name = raw_name
            if raw_name == "//":
                long_names = member_data
                if member_size & 1 and (content_end >= len(data) or data[content_end : content_end + 1] != b"\n"):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "ar_invalid_padding",
                            rel,
                            "The ar string table lacks its required padding byte.",
                        )
                    )
                    return
                offset = content_end + (member_size & 1)
                continue
            if raw_name == "/":
                if member_size & 1 and (content_end >= len(data) or data[content_end : content_end + 1] != b"\n"):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "ar_invalid_padding",
                            rel,
                            "The ar symbol table lacks its required padding byte.",
                        )
                    )
                    return
                offset = content_end + (member_size & 1)
                continue
            if raw_name.startswith("#1/"):
                try:
                    name_length = int(raw_name[3:])
                except ValueError:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "ar_invalid_extended_name",
                            rel,
                            "A BSD ar extended filename length is invalid.",
                        )
                    )
                    return
                if name_length <= 0 or name_length > len(member_data):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "ar_invalid_extended_name",
                            rel,
                            "A BSD ar extended filename exceeds its member.",
                        )
                    )
                    return
                name = member_data[:name_length].decode("utf-8", "surrogateescape").rstrip("\x00")
                member_data = member_data[name_length:]
            elif raw_name.startswith("/") and raw_name[1:].isdigit():
                index = int(raw_name[1:])
                if index >= len(long_names):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "ar_invalid_long_name",
                            rel,
                            "A GNU ar long-name reference is outside the string table.",
                        )
                    )
                    return
                end = long_names.find(b"/\n", index)
                if end < 0:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "ar_invalid_long_name",
                            rel,
                            "A GNU ar long-name reference is unterminated.",
                        )
                    )
                    return
                name = long_names[index:end].decode("utf-8", "surrogateescape")
            else:
                name = raw_name.rstrip("/")
            if not name:
                findings.append(
                    _finding(Severity.BLOCKER, "ar_empty_member_name", rel, "An ar/deb member has an empty filename.")
                )
                return
            member_rel = f"{rel}!{name}"
            names.append(name)
            budget.members += 1
            budget.expanded_bytes += len(member_data)
            if not self._check_archive_budget(member_rel, findings, budget):
                return
            self._inspect_archive_member_name(name, member_rel, findings)
            if is_deb and name == "debian-binary" and member_data != b"2.0\n":
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "deb_invalid_version",
                        member_rel,
                        "debian-binary must contain exactly the supported format marker 2.0.",
                    )
                )
            if member_mode & (stat.S_ISUID | stat.S_ISGID):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_privileged_mode",
                        member_rel,
                        "An ar/deb member carries SUID or SGID bits.",
                        mode=oct(member_mode),
                    )
                )
            if len(member_data) > self.policy.max_archive_member_bytes:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_member_size_limit",
                        member_rel,
                        "An ar/deb member exceeds the inspection limit.",
                        size=len(member_data),
                        limit=self.policy.max_archive_member_bytes,
                    )
                )
            else:
                member_type = self._detect_type(member_data, name)
                self._inspect_regular_content(
                    member_data,
                    True,
                    member_rel,
                    name,
                    member_type,
                    findings,
                    budget,
                    depth + 1,
                    is_deb,
                )
            offset = content_end
            if member_size & 1:
                if offset >= len(data) or data[offset : offset + 1] != b"\n":
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "ar_invalid_padding",
                            member_rel,
                            "An odd-sized ar/deb member lacks its newline padding byte.",
                        )
                    )
                    return
                offset += 1

        if is_deb:
            duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
            if duplicates:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "ar_duplicate_member",
                        rel,
                        "The Debian package contains duplicate ar member names.",
                        members=duplicates,
                    )
                )
            debian_binary = [name for name in names if name == "debian-binary"]
            controls = [name for name in names if name.startswith("control.tar")]
            payloads = [name for name in names if name.startswith("data.tar")]
            if len(debian_binary) != 1 or len(controls) != 1 or len(payloads) != 1:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "deb_required_members",
                        rel,
                        "A Debian package must contain exactly one debian-binary, control.tar.*, and data.tar.* member.",
                        debian_binary=len(debian_binary),
                        control=len(controls),
                        data=len(payloads),
                    )
                )
            unexpected = sorted(
                name for name in names if name not in debian_binary + controls + payloads and name != "_gpgorigin"
            )
            if unexpected:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "deb_unexpected_members",
                        rel,
                        "The Debian package contains additional top-level ar members.",
                        members=unexpected,
                    )
                )

    def _inspect_rpm(
        self,
        data: bytes,
        rel: str,
        findings: list[Finding],
        budget: _ArchiveBudget,
        depth: int,
    ) -> None:
        findings.append(
            _finding(
                Severity.REVIEW,
                "distribution_package_review",
                rel,
                "An RPM requires separate vendor-key signature verification bound to this file's SHA-256; structural parsing is not an authenticity claim.",
                package_format="rpm",
            )
        )
        if len(data) < 96 or data[:4] != b"\xed\xab\xee\xdb":
            findings.append(
                _finding(Severity.BLOCKER, "rpm_invalid_lead", rel, "The RPM lead is missing or truncated.")
            )
            return
        if data[4] not in {3, 4}:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "rpm_unsupported_version",
                    rel,
                    "The RPM lead declares an unsupported major format version.",
                    version=data[4],
                )
            )
            return
        signature_end, signature_error = _rpm_header_end(data, 96)
        if signature_error:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "rpm_invalid_signature_header",
                    rel,
                    "The RPM signature header is malformed.",
                    error=signature_error,
                )
            )
            return
        main_offset = (signature_end + 7) & ~7
        if any(data[signature_end:main_offset]):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "rpm_invalid_padding",
                    rel,
                    "The RPM signature-header alignment padding is non-zero.",
                )
            )
            return
        main_end, main_error = _rpm_header_end(data, main_offset)
        if main_error:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "rpm_invalid_main_header",
                    rel,
                    "The RPM main header is malformed.",
                    error=main_error,
                )
            )
            return
        payload = data[main_end:]
        if not payload:
            findings.append(_finding(Severity.BLOCKER, "rpm_missing_payload", rel, "The RPM contains no payload."))
            return
        budget.members += 1
        budget.expanded_bytes += len(payload)
        if not self._check_archive_budget(f"{rel}!<payload>", findings, budget):
            return
        payload_type = self._detect_type(payload, "payload")
        if payload_type in {"gzip", "bzip2", "xz"}:
            try:
                expanded = self._bounded_decompress(payload, payload_type)
            except (OSError, ValueError, zlib.error, lzma.LZMAError) as exc:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "rpm_payload_decompression_failed",
                        rel,
                        "The RPM payload could not be decompressed completely within limits.",
                        error=str(exc),
                    )
                )
                return
            budget.expanded_bytes += len(expanded)
            if not self._check_archive_budget(f"{rel}!<cpio>", findings, budget):
                return
            if expanded.startswith((b"070701", b"070702")):
                self._inspect_cpio(expanded, f"{rel}!<cpio>", findings, budget, depth + 1)
            else:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "rpm_payload_not_cpio",
                        rel,
                        "The decompressed RPM payload is not a supported newc/crc cpio archive.",
                    )
                )
        elif payload_type == "zstd":
            try:
                expanded = self._bounded_decompress(payload, "zstd")
            except (OSError, ValueError) as exc:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "rpm_payload_decompression_failed",
                        rel,
                        "The zstd RPM payload was not completely decompressed by a hash-pinned offline sandbox.",
                        error=str(exc),
                    )
                )
                return
            budget.expanded_bytes += len(expanded)
            if not self._check_archive_budget(f"{rel}!<cpio>", findings, budget):
                return
            ratio = len(expanded) / max(1, len(payload))
            if ratio > self.policy.max_compression_ratio:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_compression_ratio",
                        rel,
                        "The RPM zstd payload exceeds the permitted expansion ratio.",
                        ratio=round(ratio, 3),
                        limit=self.policy.max_compression_ratio,
                    )
                )
            elif expanded.startswith((b"070701", b"070702")):
                self._inspect_cpio(expanded, f"{rel}!<cpio>", findings, budget, depth + 1)
            else:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "rpm_payload_not_cpio",
                        rel,
                        "The decompressed RPM zstd payload is not a supported newc/crc cpio archive.",
                    )
                )
        else:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "rpm_opaque_payload",
                    rel,
                    "The RPM payload compression is not completely analyzable and cannot be approved.",
                    detected_type=payload_type,
                )
            )

    def _inspect_cpio(
        self,
        data: bytes,
        rel: str,
        findings: list[Finding],
        budget: _ArchiveBudget,
        depth: int,
    ) -> None:
        if depth >= self.policy.max_archive_depth:
            findings.append(
                _finding(
                    Severity.BLOCKER, "archive_depth_limit", rel, "Nested RPM/cpio depth exceeds the configured limit."
                )
            )
            return
        offset = 0
        saw_trailer = False
        while offset < len(data):
            if len(data) - offset < 110:
                findings.append(
                    _finding(
                        Severity.BLOCKER, "cpio_truncated_header", rel, "The cpio archive ends inside a newc header."
                    )
                )
                return
            header = data[offset : offset + 110]
            if header[:6] not in {b"070701", b"070702"}:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "cpio_invalid_magic",
                        rel,
                        "The cpio archive contains an unsupported or malformed header.",
                    )
                )
                return
            try:
                values = [int(header[start : start + 8], 16) for start in range(6, 110, 8)]
            except ValueError:
                findings.append(
                    _finding(Severity.BLOCKER, "cpio_invalid_header", rel, "A cpio newc numeric field is invalid.")
                )
                return
            mode, nlink, file_size, name_size = values[1], values[4], values[6], values[11]
            if name_size <= 0 or name_size > self.policy.max_archive_member_bytes:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "cpio_invalid_name_size",
                        rel,
                        "A cpio filename length is invalid.",
                        name_size=name_size,
                    )
                )
                return
            name_start = offset + 110
            name_end = name_start + name_size
            if name_end > len(data) or data[name_end - 1] != 0:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "cpio_truncated_name",
                        rel,
                        "A cpio filename is truncated or lacks a NUL terminator.",
                    )
                )
                return
            name = data[name_start : name_end - 1].decode("utf-8", "surrogateescape")
            content_start = (name_end + 3) & ~3
            content_end = content_start + file_size
            if content_end > len(data):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "cpio_truncated_member",
                        f"{rel}!{name}",
                        "A cpio member exceeds the payload boundary.",
                    )
                )
                return
            if header[:6] == b"070702" and (sum(data[content_start:content_end]) & 0xFFFFFFFF) != values[12]:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "cpio_checksum_mismatch",
                        f"{rel}!{name}",
                        "A crc-format cpio member failed its checksum.",
                    )
                )
                return
            if name == "TRAILER!!!":
                saw_trailer = True
                offset = (content_end + 3) & ~3
                break
            member_rel = f"{rel}!{name}"
            budget.members += 1
            budget.expanded_bytes += file_size
            if not self._check_archive_budget(member_rel, findings, budget):
                return
            self._inspect_archive_member_name(name, member_rel, findings)
            kind = stat.S_IFMT(mode)
            if mode & (stat.S_ISUID | stat.S_ISGID):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_privileged_mode",
                        member_rel,
                        "An RPM payload member carries SUID or SGID bits.",
                        mode=oct(mode),
                    )
                )
            if kind not in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_special_file",
                        member_rel,
                        "The RPM payload contains a device, FIFO, socket, or unsupported object.",
                        mode=oct(mode),
                    )
                )
            elif kind == stat.S_IFLNK:
                target = data[content_start:content_end].decode("utf-8", "surrogateescape")
                if _unsafe_link_from_member(name, target):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_link_escape",
                            member_rel,
                            "An RPM payload symlink escapes the package root.",
                            target=target,
                        )
                    )
            elif kind == stat.S_IFREG:
                if nlink > 1:
                    findings.append(
                        _finding(
                            Severity.REVIEW,
                            "archive_hardlink",
                            member_rel,
                            "An RPM payload hardlink requires explicit target/path review.",
                            nlink=nlink,
                        )
                    )
                if mode & 0o111:
                    findings.append(
                        _finding(
                            Severity.REVIEW,
                            "archive_executable_mode",
                            member_rel,
                            "An executable RPM payload member requires vendor-signature-bound review.",
                            mode=oct(mode),
                        )
                    )
                member_data = data[content_start:content_end]
                detected = self._detect_type(member_data, PurePosixPath(name).name)
                self._inspect_regular_content(
                    member_data, True, member_rel, PurePosixPath(name).name, detected, findings, budget, depth + 1, True
                )
            offset = (content_end + 3) & ~3
        if not saw_trailer:
            findings.append(
                _finding(Severity.BLOCKER, "cpio_missing_trailer", rel, "The cpio archive lacks TRAILER!!!.")
            )
        elif any(data[offset:]):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "cpio_trailing_payload",
                    rel,
                    "The cpio archive has non-zero data after TRAILER!!!.",
                )
            )

    def _inspect_archive(
        self,
        data: bytes,
        rel: str,
        detected: str,
        findings: list[Finding],
        budget: _ArchiveBudget,
        depth: int,
        package_context: bool,
    ) -> None:
        if depth >= self.policy.max_archive_depth:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_depth_limit",
                    rel,
                    "Nested archive depth exceeds the configured limit.",
                    depth=depth,
                    limit=self.policy.max_archive_depth,
                )
            )
            return
        if len(data) > self.policy.max_archive_input_bytes:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_input_limit",
                    rel,
                    "The archive is too large for bounded offline inspection.",
                    size=len(data),
                    limit=self.policy.max_archive_input_bytes,
                )
            )
            return
        if detected in {"7zip", "rar"}:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "unsupported_archive",
                    rel,
                    "This archive format cannot be safely and completely inspected with the standard-library engine.",
                    detected_type=detected,
                )
            )
            return
        try:
            if detected == "zip":
                self._inspect_zip(data, rel, findings, budget, depth, package_context)
            elif detected == "tar":
                self._inspect_tar(data, rel, findings, budget, depth, package_context)
            elif detected in {"gzip", "bzip2", "xz"}:
                # decompress explicitly with an output cap and EOF/trailing-data
                # checks before parsing a possible tar.  feeding a compressed
                # stream straight to tarfile would otherwise tolerate some
                # concatenated or opaque trailing payloads.
                expanded = self._bounded_decompress(data, detected)
                budget.members += 1
                budget.expanded_bytes += len(expanded)
                self._check_archive_budget(rel, findings, budget)
                ratio = len(expanded) / max(1, len(data))
                if ratio > self.policy.max_compression_ratio:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_compression_ratio",
                            rel,
                            "The compressed stream exceeds the permitted expansion ratio.",
                            ratio=round(ratio, 3),
                            limit=self.policy.max_compression_ratio,
                        )
                    )
                    return
                nested_rel = f"{rel}!<decompressed>"
                nested_type = self._detect_type(expanded, "decompressed")
                self._inspect_regular_content(
                    expanded,
                    True,
                    nested_rel,
                    "decompressed",
                    nested_type,
                    findings,
                    budget,
                    depth + 1,
                    package_context,
                )
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, ValueError, zlib.error, lzma.LZMAError) as exc:
            # some exception classes share OSError bases; the broad but finite
            # set is intentional.  corruption is always fail-closed.
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_parse_failed",
                    rel,
                    "The archive is corrupt, truncated, or not completely analyzable.",
                    error=str(exc),
                )
            )

    def _inspect_zip(
        self, data: bytes, rel: str, findings: list[Finding], budget: _ArchiveBudget, depth: int, package_context: bool
    ) -> None:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            eocd = data.rfind(b"PK\x05\x06")
            if eocd < 0 or eocd + 22 > len(data):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_missing_eof",
                        rel,
                        "The ZIP end-of-central-directory record is missing or truncated.",
                    )
                )
            else:
                comment_length = int.from_bytes(data[eocd + 20 : eocd + 22], "little")
                if eocd + 22 + comment_length != len(data):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_trailing_payload",
                            rel,
                            "The ZIP contains bytes after its declared end record.",
                        )
                    )
            if archive.comment:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "archive_comment",
                        rel,
                        "A ZIP archive comment requires explicit review.",
                        size=len(archive.comment),
                        sha256=hashlib.sha256(archive.comment).hexdigest(),
                    )
                )
                self._inspect_text_and_strings(archive.comment, f"{rel}!<archive-comment>", findings)
            infos = archive.infolist()
            if len(infos) > self.policy.max_archive_members:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_member_limit",
                        rel,
                        "The archive contains too many members.",
                        observed=len(infos),
                        limit=self.policy.max_archive_members,
                    )
                )
                return
            seen_names: set[str] = set()
            for info in infos:
                member_rel = f"{rel}!{info.filename}"
                budget.members += 1
                budget.expanded_bytes += info.file_size
                if not self._check_archive_budget(member_rel, findings, budget):
                    return
                self._inspect_archive_member_name(info.filename, member_rel, findings)
                if info.extra or info.comment:
                    metadata = info.extra + info.comment
                    findings.append(
                        _finding(
                            Severity.REVIEW,
                            "archive_member_metadata",
                            member_rel,
                            "A ZIP member carries extra/comment metadata that requires review.",
                            size=len(metadata),
                            sha256=hashlib.sha256(metadata).hexdigest(),
                        )
                    )
                    self._inspect_text_and_strings(metadata, f"{member_rel}!<metadata>", findings)
                normalized = info.filename.replace("\\", "/")
                if normalized in seen_names:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_duplicate_member",
                            member_rel,
                            "The archive contains duplicate member names.",
                        )
                    )
                seen_names.add(normalized)
                if info.flag_bits & 0x1:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "encrypted_archive_member",
                            member_rel,
                            "Encrypted archive members cannot be inspected and are not approvable.",
                        )
                    )
                    continue
                ratio = info.file_size / max(1, info.compress_size)
                if ratio > self.policy.max_compression_ratio:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_compression_ratio",
                            member_rel,
                            "An archive member exceeds the permitted expansion ratio.",
                            ratio=round(ratio, 3),
                            limit=self.policy.max_compression_ratio,
                        )
                    )
                    continue
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                member_kind = stat.S_IFMT(unix_mode)
                if unix_mode & (stat.S_ISUID | stat.S_ISGID):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_privileged_mode",
                            member_rel,
                            "An archive member carries SUID or SGID bits.",
                            mode=oct(unix_mode),
                        )
                    )
                if unix_mode & 0o111 and not info.is_dir():
                    severity = Severity.REVIEW if package_context else Severity.BLOCKER
                    findings.append(
                        _finding(
                            severity,
                            "archive_executable_mode",
                            member_rel,
                            "An executable archive member is not implicitly trusted.",
                            mode=oct(unix_mode),
                        )
                    )
                if member_kind not in {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_special_file",
                            member_rel,
                            "The archive contains a special filesystem object.",
                            mode=oct(unix_mode),
                        )
                    )
                    continue
                if info.is_dir():
                    continue
                if info.file_size > self.policy.max_archive_member_bytes:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_member_size_limit",
                            member_rel,
                            "An archive member exceeds the inspection limit.",
                            size=info.file_size,
                            limit=self.policy.max_archive_member_bytes,
                        )
                    )
                    continue
                try:
                    with archive.open(info, "r") as stream:
                        member_data = _bounded_read(stream, self.policy.max_archive_member_bytes)
                except (RuntimeError, zipfile.BadZipFile, EOFError, OSError) as exc:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_member_read_failed",
                            member_rel,
                            "An archive member failed decryption, CRC, or bounded reading.",
                            error=str(exc),
                        )
                    )
                    continue
                if len(member_data) != info.file_size:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_member_truncated",
                            member_rel,
                            "An archive member did not yield its complete declared content.",
                            declared=info.file_size,
                            observed=len(member_data),
                        )
                    )
                    continue
                if member_kind == stat.S_IFLNK:
                    target = member_data.decode("utf-8", "surrogateescape")
                    if _unsafe_link_from_member(info.filename, target):
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "archive_link_escape",
                                member_rel,
                                "An archive symlink escapes the archive root.",
                                target=target,
                            )
                        )
                    continue
                self._inspect_name_in_archive(info.filename, member_rel, findings)
                nested_type = self._detect_type(member_data, PurePosixPath(normalized).name)
                self._inspect_regular_content(
                    member_data,
                    True,
                    member_rel,
                    PurePosixPath(normalized).name,
                    nested_type,
                    findings,
                    budget,
                    depth + 1,
                    package_context,
                )

    def _inspect_tar(
        self, data: bytes, rel: str, findings: list[Finding], budget: _ArchiveBudget, depth: int, package_context: bool
    ) -> None:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*", errorlevel=2) as archive:
            count = 0
            local_expanded = 0
            last_member_end = 0
            seen_names: set[str] = set()
            for member in archive:
                count += 1
                if count > self.policy.max_archive_members:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_member_limit",
                            rel,
                            "The archive contains too many members.",
                            observed=count,
                            limit=self.policy.max_archive_members,
                        )
                    )
                    return
                member_rel = f"{rel}!{member.name}"
                local_expanded += max(0, member.size)
                last_member_end = max(
                    last_member_end,
                    ((member.offset_data + max(0, member.size) + 511) // 512) * 512,
                )
                budget.members += 1
                budget.expanded_bytes += max(0, member.size)
                if not self._check_archive_budget(member_rel, findings, budget):
                    return
                self._inspect_archive_member_name(member.name, member_rel, findings)
                normalized = member.name.replace("\\", "/")
                if normalized in seen_names:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_duplicate_member",
                            member_rel,
                            "The archive contains duplicate member names.",
                        )
                    )
                seen_names.add(normalized)
                if member.mode & (stat.S_ISUID | stat.S_ISGID):
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_privileged_mode",
                            member_rel,
                            "An archive member carries SUID or SGID bits.",
                            mode=oct(member.mode),
                        )
                    )
                if member.mode & 0o111 and member.isfile():
                    severity = Severity.REVIEW if package_context else Severity.BLOCKER
                    findings.append(
                        _finding(
                            severity,
                            "archive_executable_mode",
                            member_rel,
                            "An executable archive member is not implicitly trusted.",
                            mode=oct(member.mode),
                        )
                    )
                if member.isdev() or member.isfifo():
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_special_file",
                            member_rel,
                            "The archive contains a device node or FIFO.",
                        )
                    )
                    continue
                if member.issym() or member.islnk():
                    if _unsafe_link_from_member(member.name, member.linkname, hardlink=member.islnk()):
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "archive_link_escape",
                                member_rel,
                                "An archive link escapes the archive root.",
                                target=member.linkname,
                            )
                        )
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_unusual_member",
                            member_rel,
                            "The archive member has an unsupported type.",
                            type=member.type.decode("latin1", "replace")
                            if isinstance(member.type, bytes)
                            else str(member.type),
                        )
                    )
                    continue
                if member.size > self.policy.max_archive_member_bytes:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_member_size_limit",
                            member_rel,
                            "An archive member exceeds the inspection limit.",
                            size=member.size,
                            limit=self.policy.max_archive_member_bytes,
                        )
                    )
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_member_read_failed",
                            member_rel,
                            "A regular archive member could not be read.",
                        )
                    )
                    continue
                try:
                    member_data = _bounded_read(stream, self.policy.max_archive_member_bytes)
                finally:
                    stream.close()
                if len(member_data) != member.size:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "archive_member_truncated",
                            member_rel,
                            "An archive member did not yield its complete declared content.",
                            declared=member.size,
                            observed=len(member_data),
                        )
                    )
                    continue
                nested_type = self._detect_type(member_data, PurePosixPath(normalized).name)
                self._inspect_regular_content(
                    member_data,
                    True,
                    member_rel,
                    PurePosixPath(normalized).name,
                    nested_type,
                    findings,
                    budget,
                    depth + 1,
                    package_context,
                )

            trailer = data[last_member_end:]
            if len(trailer) < 1024 or any(trailer):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_trailing_payload",
                        rel,
                        "The tar archive lacks two clean end blocks or contains an appended payload.",
                        trailing_bytes=len(trailer),
                    )
                )
            if count and local_expanded / max(1, len(data)) > self.policy.max_compression_ratio:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_compression_ratio",
                        rel,
                        "The archive exceeds the permitted aggregate expansion ratio.",
                        ratio=round(local_expanded / max(1, len(data)), 3),
                        limit=self.policy.max_compression_ratio,
                    )
                )

    def _inspect_archive_member_name(self, name: str, member_rel: str, findings: list[Finding]) -> None:
        if _unsafe_archive_path(name):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_path_traversal",
                    member_rel,
                    "The archive contains an absolute, drive-qualified, or traversal path.",
                    member=name,
                )
            )
        self._inspect_name_in_archive(name, member_rel, findings)

    def _inspect_name_in_archive(self, name: str, member_rel: str, findings: list[Finding]) -> None:
        normalized = name.replace("\\", "/")
        for component in PurePosixPath(normalized).parts:
            if component.startswith(".") and component not in {".", ".."}:
                findings.append(
                    _finding(
                        Severity.REVIEW,
                        "archive_hidden_name",
                        member_rel,
                        "The archive contains a hidden member.",
                        component=component,
                    )
                )
            if any(unicodedata.category(char) in {"Cf", "Cc", "Cs"} for char in component):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "archive_invisible_name",
                        member_rel,
                        "An archive member name contains invisible, control, or undecodable characters.",
                    )
                )
        lowered = normalized.lower()
        if lowered.endswith("vbaproject.bin") or "/embeddings/" in f"/{lowered}" or lowered.endswith("oleobject.bin"):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "office_active_content",
                    member_rel,
                    "The office/archive container contains macros or embedded active objects.",
                )
            )
        if lowered.endswith((".ko", ".efi", ".rom", ".fw")) or any(
            token in lowered for token in ("boot/", "initramfs", "lib/modules/", "firmware/")
        ):
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_boot_kernel_firmware",
                    member_rel,
                    "The archive contains boot, kernel-module, or firmware material.",
                )
            )

    def _check_archive_budget(self, rel: str, findings: list[Finding], budget: _ArchiveBudget) -> bool:
        okay = True
        if budget.members > self.policy.max_archive_members:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_global_member_limit",
                    rel,
                    "Nested archives exceed the global member limit.",
                    observed=budget.members,
                    limit=self.policy.max_archive_members,
                )
            )
            okay = False
        if budget.expanded_bytes > self.policy.max_archive_expanded_bytes:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "archive_expansion_limit",
                    rel,
                    "Nested archives exceed the global expanded-byte limit.",
                    observed=budget.expanded_bytes,
                    limit=self.policy.max_archive_expanded_bytes,
                )
            )
            okay = False
        return okay

    def _bounded_decompress(self, data: bytes, detected: str) -> bytes:
        limit = self.policy.max_archive_member_bytes
        if detected == "gzip":
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            output = decompressor.decompress(data, limit + 1)
            if len(output) > limit or decompressor.unconsumed_tail:
                raise ValueError("decompressed stream exceeds configured limit")
            output += decompressor.flush(limit + 1 - len(output))
            if len(output) > limit or not decompressor.eof:
                raise ValueError("gzip stream is truncated or exceeds configured limit")
            if decompressor.unused_data:
                raise ValueError("gzip stream has trailing or concatenated data")
            return output
        if detected == "bzip2":
            decompressor = bz2.BZ2Decompressor()
            output = decompressor.decompress(data, max_length=limit + 1)
            if len(output) > limit or not decompressor.eof or decompressor.unused_data:
                raise ValueError("bzip2 stream is truncated, concatenated, or exceeds configured limit")
            return output
        if detected == "xz":
            decompressor = lzma.LZMADecompressor()
            output = decompressor.decompress(data, max_length=limit + 1)
            if len(output) > limit or not decompressor.eof or decompressor.unused_data:
                raise ValueError("xz stream is truncated, concatenated, or exceeds configured limit")
            return output
        if detected == "zstd":
            return self._bounded_zstd_decompress(data, limit)
        raise ValueError(f"unsupported compression format: {detected}")

    def _bounded_zstd_decompress(self, data: bytes, limit: int) -> bytes:
        """decompress zstd only in a pinned no-network sandbox with an output cap."""

        if len(data) > self.policy.max_archive_input_bytes:
            raise ValueError("zstd input exceeds the configured archive limit")
        with tempfile.TemporaryDirectory(prefix="umzug-zstd-") as temp_name:
            private_root = Path(temp_name)
            os.chmod(private_root, 0o700)
            tool_root = private_root / "tools"
            tool_root.mkdir(mode=0o700)
            tool_snapshots: dict[str, Path] = {}
            for name in ("zstd", "bwrap"):
                evidence, snapshot = self._capture_tool_snapshot(name, tool_root / name)
                if snapshot is None or not evidence.verified:
                    detail = evidence.error or "missing or unverified executable"
                    raise ValueError(f"{name} executable does not match its independently pinned SHA-256: {detail}")
                tool_snapshots[name] = snapshot
            source = private_root / "input.zst"
            fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fchmod(fd, 0o400)
                os.fsync(fd)
            finally:
                os.close(fd)
            command = [
                str(tool_snapshots["bwrap"]),
                "--die-with-parent",
                "--new-session",
                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-ipc",
                "--unshare-uts",
                "--unshare-cgroup-try",
                "--cap-drop",
                "ALL",
                *minimal_bwrap_runtime(),
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/analysis",
                "--ro-bind",
                str(source),
                "/analysis/input.zst",
                "--dir",
                "/analysis/tools",
                "--ro-bind",
                str(tool_snapshots["zstd"]),
                "/analysis/tools/zstd",
                "--ro-bind",
                str(tool_snapshots["bwrap"]),
                "/analysis/tools/bwrap",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/home",
                "--tmpfs",
                "/root",
                "--chdir",
                "/analysis",
                "--clearenv",
                "--setenv",
                "PATH",
                "/analysis/tools",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--setenv",
                "LC_ALL",
                "C.UTF-8",
                "--",
                "/analysis/tools/zstd",
                "--decompress",
                "--stdout",
                "--quiet",
                "-M128",
                "--",
                "/analysis/input.zst",
            ]
            stderr_file = tempfile.TemporaryFile()
            process: subprocess.Popen[bytes] | None = None
            output = bytearray()
            deadline = time.monotonic() + self.policy.external_timeout_seconds
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=stderr_file,
                    env={"PATH": "/nonexistent", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                    shell=False,
                    close_fds=True,
                    preexec_fn=self._restrict_parser_resources,
                )
                if process.stdout is None:
                    raise ValueError("zstd sandbox stdout pipe is unavailable")
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ)
                try:
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ValueError("zstd sandbox timed out")
                        events = selector.select(remaining)
                        if not events:
                            raise ValueError("zstd sandbox timed out")
                        chunk = os.read(process.stdout.fileno(), min(_CHUNK_SIZE, limit + 1 - len(output)))
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > limit:
                            raise ValueError("zstd expansion exceeds the configured output limit")
                finally:
                    selector.close()
                returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
                if returncode != 0:
                    stderr_file.seek(0)
                    detail = stderr_file.read(1000).decode("utf-8", "replace").strip()
                    raise ValueError(f"zstd sandbox failed with exit {returncode}: {detail}")
                return bytes(output)
            except subprocess.TimeoutExpired as exc:
                raise ValueError("zstd sandbox timed out") from exc
            except (OSError, subprocess.SubprocessError) as exc:
                raise ValueError(f"zstd sandbox failed safely: {type(exc).__name__}") from exc
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()
                stderr_file.close()

    def _capture_tool_snapshot(
        self,
        name: str,
        destination: Path,
    ) -> tuple[ToolEvidence, Path | None]:
        expected = self.policy.trusted_tool_hashes.get(name)
        executable = shutil.which(name)
        if not executable:
            return (
                ToolEvidence(name, None, None, None, expected, False, False, "not found in PATH"),
                None,
            )
        source: Path | None = None
        try:
            source = Path(executable).resolve(strict=True)
            digest, _captured, _total = _snapshot_regular_path(
                source,
                destination,
                max_bytes=_MAX_SCANNER_TOOL_BYTES,
                mode=0o500,
            )
        except (OSError, ScannerError) as exc:
            return (
                ToolEvidence(
                    name,
                    str(source or executable),
                    None,
                    None,
                    expected,
                    True,
                    False,
                    str(exc),
                ),
                None,
            )
        verified = bool(expected and _constant_time_hex_equal(digest, expected))
        return (
            ToolEvidence(name, str(source), None, digest, expected, True, verified, None),
            destination,
        )

    def _discover_tools(
        self,
        findings: list[Finding],
        snapshot_root: Path,
    ) -> tuple[dict[str, ToolEvidence], dict[str, Path]]:
        del findings
        snapshot_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(snapshot_root, 0o700)
        result: dict[str, ToolEvidence] = {}
        snapshots: dict[str, Path] = {}
        for name in ("file", "clamscan", "yara", "bwrap", "zstd"):
            evidence, snapshot = self._capture_tool_snapshot(name, snapshot_root / name)
            # even ``--version`` executes tool code.  defer it until the
            # isolation namespace is active; strict scans never start an
            # unverified executable merely to identify it.
            result[name] = evidence
            if snapshot is not None:
                snapshots[name] = snapshot
        return result, snapshots

    def _capture_material_set(
        self,
        paths: Sequence[Path],
        trusted: Mapping[str, str],
        snapshot_root: Path,
        prefix: str,
    ) -> tuple[_MaterialSnapshot, ...]:
        snapshot_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(snapshot_root, 0o700)
        captured: list[_MaterialSnapshot] = []
        for index, configured in enumerate(paths):
            configured_text = str(configured)
            source = Path(configured).expanduser().absolute()
            expected = trusted.get(configured_text) or trusted.get(str(source))
            destination = snapshot_root / f"{prefix}-{index}"
            try:
                digest, is_directory, _total = _snapshot_path_or_tree(
                    source,
                    destination,
                    max_files=self.policy.max_files,
                    max_file_bytes=self.policy.max_archive_input_bytes,
                    max_total_bytes=self.policy.max_archive_expanded_bytes,
                )
            except (OSError, ScannerError) as exc:
                captured.append(
                    _MaterialSnapshot(
                        configured_text,
                        str(source),
                        None,
                        None,
                        expected,
                        False,
                        False,
                        str(exc),
                    )
                )
                continue
            captured.append(
                _MaterialSnapshot(
                    configured_text,
                    str(source),
                    destination,
                    digest,
                    expected,
                    bool(expected and _constant_time_hex_equal(digest, expected)),
                    is_directory,
                    None,
                )
            )
        return tuple(captured)

    def _check_external_material(
        self,
        findings: list[Finding],
        tools: Mapping[str, ToolEvidence],
        trust: _ScannerTrustSnapshots,
    ) -> None:
        if not self.policy.strict_external:
            return
        if self.policy.external_isolation_backend != "bubblewrap":
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "external_isolation_disabled",
                    ".",
                    "Strict policy requires an offline network and process namespace for external scanners.",
                    configured_backend=self.policy.external_isolation_backend,
                )
            )
        else:
            isolator = tools.get("bwrap")
            if isolator is None or not isolator.available:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "external_isolator_missing",
                        ".",
                        "Bubblewrap is required to isolate external scanners from the network and host writes.",
                    )
                )
            elif self.policy.require_verified_external_material and not isolator.verified:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "external_isolator_unverified",
                        ".",
                        "The Bubblewrap executable is not bound to its configured trusted SHA-256 digest.",
                        observed_sha256=isolator.sha256,
                        expected_sha256=isolator.expected_sha256,
                    )
                )
        for name in self.policy.required_external_scanners:
            evidence = tools.get(name)
            if evidence is None or not evidence.available:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "required_scanner_missing",
                        ".",
                        "A required independent scanner is unavailable.",
                        scanner=name,
                    )
                )
                continue
            if self.policy.require_verified_external_material and not evidence.verified:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "scanner_binary_unverified",
                        ".",
                        "A scanner executable is not bound to its configured trusted SHA-256 digest.",
                        scanner=name,
                        observed_sha256=evidence.sha256,
                        expected_sha256=evidence.expected_sha256,
                    )
                )
            if evidence.error:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "scanner_version_failed",
                        ".",
                        "A scanner version could not be recorded reliably.",
                        scanner=name,
                        error=evidence.error,
                    )
                )

        if "yara" in self.policy.required_external_scanners:
            self._check_material_set(
                "yara_rule",
                trust.yara_rules,
                findings,
            )
        if "clamscan" in self.policy.required_external_scanners:
            if len(self.policy.clam_signature_paths) != 1:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "clam_signature_configuration_ambiguous",
                        ".",
                        "Strict ClamAV scans require exactly one pinned database file or directory because clamscan accepts one --database=FILE/DIR source.",
                        configured_paths=len(self.policy.clam_signature_paths),
                    )
                )
            self._check_material_set(
                "clam_signature",
                trust.clam_signatures,
                findings,
            )

    def _check_material_set(
        self,
        kind: str,
        snapshots: Sequence[_MaterialSnapshot],
        findings: list[Finding],
    ) -> None:
        if not snapshots:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    f"{kind}_missing",
                    ".",
                    "No cryptographically pinned offline analysis material was configured.",
                )
            )
            return
        for snapshot in snapshots:
            if snapshot.error or snapshot.snapshot_path is None:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        f"{kind}_unreadable",
                        ".",
                        "Configured analysis material could not be captured safely.",
                        material_path=snapshot.source_path or snapshot.configured_path,
                        error=snapshot.error,
                    )
                )
                continue
            if not snapshot.verified:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        f"{kind}_unverified",
                        ".",
                        "Captured analysis material does not match a configured trusted SHA-256 digest.",
                        material_path=snapshot.source_path,
                        observed_sha256=snapshot.sha256,
                        expected_sha256=snapshot.expected_sha256,
                    )
                )

    def _run_external_scanners(
        self,
        root: Path,
        regular_paths: Sequence[tuple[Path, str]],
        tools: Mapping[str, ToolEvidence],
        findings: list[Finding],
        detected_types: Mapping[str, str | None],
        trust: _ScannerTrustSnapshots,
    ) -> list[ExternalScanResult]:
        if not self.policy.run_external_scanners:
            if self.policy.strict_external:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "external_scanners_not_run",
                        ".",
                        "External scanners were required but execution was disabled.",
                    )
                )
            return []
        if self.policy.strict_external and self.policy.require_verified_external_material:
            required_tools = (*self.policy.required_external_scanners, "bwrap")
            if any(name not in trust.tools or name not in tools or not tools[name].verified for name in required_tools):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "external_trust_snapshot_incomplete",
                        ".",
                        "External scanners were not started because a required verified private tool snapshot is absent.",
                    )
                )
                return []
            if "yara" in self.policy.required_external_scanners and (
                not trust.yara_rules or any(row.snapshot_path is None or not row.verified for row in trust.yara_rules)
            ):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "external_trust_snapshot_incomplete",
                        ".",
                        "YARA was not started because a verified private rule snapshot is absent.",
                    )
                )
                return []
            if "clamscan" in self.policy.required_external_scanners and (
                len(trust.clam_signatures) != 1
                or trust.clam_signatures[0].snapshot_path is None
                or not trust.clam_signatures[0].verified
            ):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "external_trust_snapshot_incomplete",
                        ".",
                        "ClamAV was not started because one verified private database snapshot is required.",
                    )
                )
                return []
        results: list[ExternalScanResult] = []
        isolation_prefix = self._establish_external_isolation(root, tools, findings, results, trust)
        if isolation_prefix is None:
            return results
        self._record_isolated_versions(root, tools, isolation_prefix, findings, results, trust)
        file_tool = tools.get("file")
        file_snapshot = trust.tools.get("file")
        if file_tool and file_tool.available and file_snapshot is not None:
            file_command = "/analysis/tools/file" if isolation_prefix else str(file_snapshot)
            for path, rel in regular_paths:
                target = _sandbox_candidate_path(path, root) if isolation_prefix else str(path)
                result = self._invoke_tool(
                    "file", [*isolation_prefix, file_command, "--brief", "--mime-type", "--", target], rel, root
                )
                results.append(result)
                if result.returncode != 0:
                    severity = Severity.BLOCKER if self.policy.strict_external else Severity.REVIEW
                    findings.append(
                        _finding(
                            severity,
                            "file_tool_failed",
                            rel,
                            "The independent file-type detector failed.",
                            returncode=result.returncode,
                            error=result.error,
                        )
                    )
                elif result.output and not _mime_agrees(detected_types.get(rel), result.output):
                    severity = Severity.BLOCKER if self.policy.strict_external else Severity.REVIEW
                    findings.append(
                        _finding(
                            severity,
                            "independent_type_disagreement",
                            rel,
                            "Built-in magic inspection and file(1) disagree about content type.",
                            builtin=detected_types.get(rel),
                            file_mime=result.output,
                        )
                    )

        clam = tools.get("clamscan")
        clam_snapshot = trust.tools.get("clamscan")
        if clam and clam.available and clam_snapshot is not None:
            if len(self.policy.clam_signature_paths) != 1:
                severity = Severity.BLOCKER if self.policy.strict_external else Severity.INFO
                findings.append(
                    _finding(
                        severity,
                        "clamav_database_not_bound",
                        ".",
                        "ClamAV was not started because exactly one explicit pinned database file or directory is required.",
                        configured_paths=len(self.policy.clam_signature_paths),
                    )
                )
                clam = None
        if clam and clam.available and clam_snapshot is not None:
            clam_command = "/analysis/tools/clamscan" if isolation_prefix else str(clam_snapshot)
            args = [
                clam_command,
                "--recursive=yes",
                "--infected",
                "--no-summary",
                "--follow-dir-symlinks=0",
                "--follow-file-symlinks=0",
                "--cross-fs=no",
                "--heuristic-alerts=yes",
                "--alert-broken=yes",
                "--alert-encrypted=yes",
                "--tempdir=/tmp",
                f"--bytecode-timeout={self.policy.external_timeout_seconds * 1000}",
                f"--max-filesize={self.policy.max_archive_member_bytes}",
                f"--max-scansize={self.policy.max_archive_expanded_bytes}",
                f"--max-recursion={self.policy.max_archive_depth}",
                f"--max-files={self.policy.max_archive_members}",
            ]
            database = trust.clam_signatures[0] if len(trust.clam_signatures) == 1 else None
            if database is None or database.snapshot_path is None:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "clamav_database_snapshot_missing",
                        ".",
                        "ClamAV was not started because its private database snapshot is absent.",
                    )
                )
                return results
            database_argument = "/analysis/clam-db" if isolation_prefix else str(database.snapshot_path)
            args.append(f"--database={database_argument}")
            args.extend(("--", "/input" if isolation_prefix else str(root)))
            result = self._invoke_tool("clamscan", [*isolation_prefix, *args], ".", root)
            results.append(result)
            if result.returncode == 1:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "clamav_detection",
                        ".",
                        "ClamAV reported one or more detections.",
                        output=result.output,
                    )
                )
            elif result.returncode != 0:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "clamav_failed",
                        ".",
                        "ClamAV did not complete successfully.",
                        returncode=result.returncode,
                        error=result.error,
                        output=result.output,
                    )
                )

        yara = tools.get("yara")
        yara_snapshot = trust.tools.get("yara")
        if yara and yara.available and yara_snapshot is not None:
            yara_command = "/analysis/tools/yara" if isolation_prefix else str(yara_snapshot)
            for rule_index, rules in enumerate(trust.yara_rules):
                if rules.snapshot_path is None:
                    findings.append(
                        _finding(
                            Severity.BLOCKER,
                            "yara_rule_snapshot_missing",
                            ".",
                            "YARA was not started because a private rule snapshot is absent.",
                            rule_index=rule_index,
                        )
                    )
                    continue
                for path, rel in regular_paths:
                    if path.lstat().st_size > self.policy.max_inspect_bytes:
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "yara_size_limit",
                                rel,
                                "YARA was not allowed to consume a file beyond the configured bounded inspection size.",
                            )
                        )
                        continue
                    rules_argument = f"/analysis/yara-{rule_index}" if isolation_prefix else str(rules.snapshot_path)
                    target = _sandbox_candidate_path(path, root) if isolation_prefix else str(path)
                    result = self._invoke_tool(
                        "yara",
                        [
                            *isolation_prefix,
                            yara_command,
                            f"--timeout={self.policy.external_timeout_seconds}",
                            rules_argument,
                            target,
                        ],
                        rel,
                        root,
                    )
                    results.append(result)
                    if result.returncode != 0:
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "yara_failed",
                                rel,
                                "YARA did not complete successfully.",
                                returncode=result.returncode,
                                error=result.error,
                            )
                        )
                    elif result.output:
                        findings.append(
                            _finding(
                                Severity.BLOCKER,
                                "yara_detection",
                                rel,
                                "One or more YARA rules matched.",
                                matches=result.output,
                            )
                        )
        return results

    def _establish_external_isolation(
        self,
        root: Path,
        tools: Mapping[str, ToolEvidence],
        findings: list[Finding],
        results: list[ExternalScanResult],
        trust: _ScannerTrustSnapshots,
    ) -> list[str] | None:
        """return a verified offline/read-only namespace wrapper or fail closed.

        bubblewrap's network and PID namespaces remove host network interfaces
        and contain scanner processes.  only runtime trees, the candidate and
        pinned analysis material are visible; host data/config trees are absent.
        """

        backend = self.policy.external_isolation_backend
        if backend == "none":
            if self.policy.strict_external:
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "external_isolation_unavailable",
                        ".",
                        "External scanners were not started because strict isolation is unavailable.",
                    )
                )
                return None
            if not self.policy.allow_unisolated_external_in_relaxed_mode:
                findings.append(
                    _finding(
                        Severity.INFO,
                        "external_scanners_skipped_unisolated",
                        ".",
                        "External scanners were skipped because relaxed policy did not authorize direct execution.",
                    )
                )
                return None
            findings.append(
                _finding(
                    Severity.REVIEW,
                    "external_scanners_unisolated",
                    ".",
                    "External scanners were explicitly allowed to run without network/process isolation in relaxed mode.",
                )
            )
            return []

        isolator = tools.get("bwrap")
        isolator_snapshot = trust.tools.get("bwrap")
        if isolator is None or not isolator.available or isolator_snapshot is None:
            severity = Severity.BLOCKER if self.policy.strict_external else Severity.INFO
            findings.append(
                _finding(
                    severity,
                    "external_isolation_unavailable",
                    ".",
                    "Bubblewrap is unavailable; external scanners were not started.",
                )
            )
            return None
        if self.policy.strict_external and self.policy.require_verified_external_material and not isolator.verified:
            findings.append(
                _finding(
                    Severity.BLOCKER,
                    "external_isolation_unavailable",
                    ".",
                    "Unverified Bubblewrap was not executed under strict policy.",
                )
            )
            return None

        prefix = [
            str(isolator_snapshot),
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--cap-drop",
            "ALL",
            *minimal_bwrap_runtime(),
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/analysis",
            "--ro-bind",
            str(root),
            "/input",
            "--dir",
            "/analysis/tools",
            "--chdir",
            "/",
            "--clearenv",
            "--setenv",
            "PATH",
            "/analysis/tools",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "TZ",
            "UTC",
            "--",
        ]
        # only private captures are exposed at deterministic paths.  original
        # executable, rule and database paths are never mounted or executed.
        prefix.pop()
        for name, snapshot in sorted(trust.tools.items()):
            if not re.fullmatch(r"[a-z0-9-]+", name):
                findings.append(
                    _finding(
                        Severity.BLOCKER,
                        "isolation_tool_name_invalid",
                        ".",
                        "A private scanner tool snapshot has an unsafe internal name.",
                    )
                )
                return None
            prefix.extend(("--ro-bind", str(snapshot), f"/analysis/tools/{name}"))
        for index, rules in enumerate(trust.yara_rules):
            if rules.snapshot_path is not None:
                prefix.extend(("--ro-bind", str(rules.snapshot_path), f"/analysis/yara-{index}"))
        if len(trust.clam_signatures) == 1 and trust.clam_signatures[0].snapshot_path is not None:
            prefix.extend(("--ro-bind", str(trust.clam_signatures[0].snapshot_path), "/analysis/clam-db"))
        # hide host-writable locations only after binding candidate and rules;
        # otherwise a candidate physically located below /home or /tmp would
        # disappear before bubblewrap could bind it at /input.
        prefix.extend(("--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/home", "--tmpfs", "/root"))
        prefix.append("--")
        # use the already hash-pinned isolator itself as the probe payload;
        # introducing an unpinned `true` binary would weaken the trust chain.
        probe = self._invoke_tool("isolation-probe", [*prefix, "/analysis/tools/bwrap", "--version"], ".", root)
        results.append(probe)
        if probe.returncode != 0:
            severity = Severity.BLOCKER if self.policy.strict_external else Severity.INFO
            findings.append(
                _finding(
                    severity,
                    "external_isolation_probe_failed",
                    ".",
                    "Bubblewrap could not establish the required offline read-only namespaces; scanners were not started.",
                    returncode=probe.returncode,
                    error=probe.error,
                    output=probe.output,
                )
            )
            return None
        return prefix

    def _record_isolated_versions(
        self,
        root: Path,
        tools: Mapping[str, ToolEvidence],
        prefix: Sequence[str],
        findings: list[Finding],
        results: list[ExternalScanResult],
        trust: _ScannerTrustSnapshots,
    ) -> None:
        mutable_tools = tools if isinstance(tools, dict) else None
        for name, evidence in tuple(tools.items()):
            snapshot = trust.tools.get(name)
            if not evidence.available or snapshot is None:
                continue
            if self.policy.strict_external and self.policy.require_verified_external_material and not evidence.verified:
                continue
            command = f"/analysis/tools/{name}" if prefix else str(snapshot)
            result = self._invoke_tool(f"{name}-version", [*prefix, command, "--version"], ".", root)
            results.append(result)
            version = result.output.splitlines()[0] if result.returncode == 0 and result.output else None
            error = result.error
            if result.returncode != 0 or version is None:
                error = error or (
                    f"version command returned {result.returncode}"
                    if result.returncode != 0
                    else "version command produced no output"
                )
                severity = Severity.BLOCKER if self.policy.strict_external else Severity.REVIEW
                findings.append(
                    _finding(
                        severity,
                        "scanner_version_failed",
                        ".",
                        "An isolated tool version could not be recorded reliably.",
                        scanner=name,
                        returncode=result.returncode,
                        error=error,
                    )
                )
            if mutable_tools is not None:
                mutable_tools[name] = dataclasses.replace(evidence, version=version, error=error)

    def _restrict_parser_resources(self) -> None:
        """apply hard per-process limits before untrusted bytes reach a parser."""

        limits = (
            ("RLIMIT_FSIZE", self.policy.max_external_output_bytes + 1),
            ("RLIMIT_AS", self.policy.max_external_address_space_bytes),
            ("RLIMIT_CPU", self.policy.max_external_cpu_seconds),
            ("RLIMIT_NPROC", self.policy.max_external_processes),
            ("RLIMIT_NOFILE", self.policy.max_external_open_files),
            ("RLIMIT_CORE", 0),
        )
        for resource_name, requested in limits:
            resource_id = getattr(resource, resource_name, None)
            if resource_id is None:
                raise OSError(f"required parser resource limit is unavailable: {resource_name}")
            _soft, hard = resource.getrlimit(resource_id)
            effective = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
            resource.setrlimit(resource_id, (effective, effective))

    def _invoke_tool(self, name: str, args: Sequence[str], rel: str, root: Path) -> ExternalScanResult:

        try:
            with tempfile.TemporaryFile() as output_file:
                completed = subprocess.run(
                    list(args),
                    stdin=subprocess.DEVNULL,
                    stdout=output_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.policy.external_timeout_seconds,
                    check=False,
                    env=_scanner_env(),
                    shell=False,
                    close_fds=True,
                    preexec_fn=self._restrict_parser_resources,
                )
                output_file.seek(0)
                raw_output = output_file.read(self.policy.max_external_output_bytes + 1)
            if len(raw_output) > self.policy.max_external_output_bytes:
                return ExternalScanResult(
                    name,
                    rel,
                    completed.returncode,
                    "output-limit",
                    _safe_display_output(raw_output, root, self.policy.max_external_output_bytes),
                    "tool output exceeded the configured bound",
                )
            output = _safe_display_output(raw_output, root, self.policy.max_external_output_bytes)
            return ExternalScanResult(name, rel, completed.returncode, "completed", output)
        except subprocess.TimeoutExpired as exc:
            return ExternalScanResult(
                name,
                rel,
                None,
                "timeout",
                "",
                f"timeout after {self.policy.external_timeout_seconds}s",
            )
        except UmzugError as exc:
            return ExternalScanResult(name, rel, None, "error", "", str(exc))
        except (OSError, subprocess.SubprocessError) as exc:
            return ExternalScanResult(name, rel, None, "error", "", str(exc))


class ZeroTrustPipeline:
    """enforce explicit, hash-bound transitions between trust zones."""

    _CANDIDATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

    def __init__(self, workspace: Path | str, scanner: ZeroTrustScanner | None = None) -> None:
        self.workspace = Path(workspace).absolute()
        self.scanner = scanner or ZeroTrustScanner()
        self.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.workspace, 0o700)
        for stage in Stage:
            directory = self.workspace / stage.value
            directory.mkdir(mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
        (self.workspace / "state" / "reports").mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.workspace / "state" / "approvals").mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.workspace / "state" / "promotions").mkdir(mode=0o700, parents=True, exist_ok=True)

    def stage_path(self, stage: Stage, candidate: str) -> Path:
        self._validate_candidate(candidate)
        return self.workspace / stage.value / candidate

    def ingest(self, source: Path | str, candidate: str) -> IngestResult:
        """snapshot input into SOURCE, then make an inert QUARANTINE copy.

        no input is followed through a symlink, no special file is recreated,
        executable/privileged bits and xattrs are stripped in the copies.  the
        source report retains evidence of those original attributes.
        """

        self._validate_candidate(candidate)
        source = Path(source).absolute()
        if self.scanner.policy.require_secure_source_mount:
            preflight = self.scanner.validate_source_mount(source)
            if any(finding.severity is Severity.BLOCKER for finding in preflight):
                raise UnsafeInputError("SOURCE is not on a verified ro,noexec,nodev,nosuid mount")
        source_report = self.scanner.scan(source, Stage.SOURCE)
        mount_blockers = {
            "source_mount_unknown",
            "source_mount_insecure",
        }
        if self.scanner.policy.require_secure_source_mount and any(
            finding.rule in mount_blockers for finding in source_report.blockers
        ):
            raise UnsafeInputError("SOURCE is not on a verified ro,noexec,nodev,nosuid mount")
        source_dest = self.stage_path(Stage.SOURCE, candidate)
        quarantine_dest = self.stage_path(Stage.QUARANTINE, candidate)
        _safe_copy_atomic(source, source_dest, inert=True)
        _safe_copy_atomic(source_dest, quarantine_dest, inert=True)
        _make_tree_read_only(source_dest)
        source_snapshot_manifest = self.scanner.current_manifest_sha256(source_dest)
        quarantine_report = self.scanner.scan(quarantine_dest, Stage.QUARANTINE)
        self._write_report(candidate, Stage.SOURCE, source_report)
        self._write_report(candidate, Stage.QUARANTINE, quarantine_report)
        quarantine_report.write_json(self.workspace / "state" / "reports" / f"{candidate}.quarantine.ingest.json")
        provenance = {
            "schema_version": SCHEMA_VERSION,
            "receipt_type": "source-to-quarantine",
            "candidate": candidate,
            "ingested_at": _now(),
            "original_source": str(source),
            "source_mount_enforced": self.scanner.policy.require_secure_source_mount,
            "source_report_scan_id": source_report.scan_id,
            "source_report_sha256": _canonical_json_hash(source_report.to_dict()),
            "source_manifest_sha256": source_report.manifest_sha256,
            "source_snapshot_manifest_sha256": source_snapshot_manifest,
            "quarantine_report_scan_id": quarantine_report.scan_id,
            "quarantine_report_sha256": _canonical_json_hash(quarantine_report.to_dict()),
            "quarantine_manifest_sha256": quarantine_report.manifest_sha256,
        }
        provenance["provenance_sha256"] = _canonical_json_hash(provenance)
        _atomic_write_text(
            self.workspace / "state" / f"{candidate}.provenance.json",
            json.dumps(provenance, sort_keys=True, indent=2) + "\n",
            0o600,
        )
        return IngestResult(candidate, source_report, quarantine_report)

    def promote_to_sanitized(
        self,
        candidate: str,
        report: ScanReport,
        *,
        accepted_findings: Iterable[str] = (),
    ) -> ScanReport:
        """explicitly copy a completely inspected quarantine candidate.

        this is not approval.  blockers can never be acknowledged away;
        review findings must be named explicitly and are re-evaluated later.
        """

        source = self.stage_path(Stage.QUARANTINE, candidate)
        if report.stage is not Stage.QUARANTINE or Path(report.root) != source:
            raise ApprovalError("the report is not for this candidate's QUARANTINE stage")
        accepted = tuple(sorted(set(accepted_findings)))
        unresolved = report.unresolved(accepted)
        if unresolved:
            raise ApprovalError(f"candidate has {len(unresolved)} unresolved finding(s)")
        review_ids = {finding.id for finding in report.reviews}
        if set(accepted) != review_ids:
            raise ApprovalError("promotion acceptance must name exactly the QUARANTINE review findings")
        self.scanner.assert_unchanged(report)
        provenance = self._load_ingest_provenance(candidate)
        if not hmac.compare_digest(
            str(provenance["source_snapshot_manifest_sha256"]),
            self.scanner.current_manifest_sha256(self.stage_path(Stage.SOURCE, candidate)),
        ):
            raise IntegrityError("SOURCE snapshot changed after its ingest provenance was recorded")
        if provenance["quarantine_manifest_sha256"] != report.manifest_sha256:
            raise IntegrityError("QUARANTINE manifest differs from the ingest provenance")
        destination = self.stage_path(Stage.SANITIZED, candidate)
        _safe_copy_atomic(source, destination, inert=True)
        sanitized_report = self.scanner.scan(destination, Stage.SANITIZED)
        # persist the exact QUARANTINE report whose scan ID/hash and explicit
        # review acknowledgements enter the promotion receipt.
        self._write_report(candidate, Stage.QUARANTINE, report)
        self._write_report(candidate, Stage.SANITIZED, sanitized_report)
        promotion = {
            "schema_version": SCHEMA_VERSION,
            "receipt_type": "quarantine-to-sanitized",
            "candidate": candidate,
            "promoted_at": _now(),
            "source_stage": Stage.QUARANTINE.value,
            "target_stage": Stage.SANITIZED.value,
            "ingest_provenance_sha256": provenance["provenance_sha256"],
            "source_snapshot_manifest_sha256": provenance["source_snapshot_manifest_sha256"],
            "quarantine_report_scan_id": report.scan_id,
            "quarantine_report_sha256": _canonical_json_hash(report.to_dict()),
            "quarantine_manifest_sha256": report.manifest_sha256,
            "accepted_findings": list(accepted),
            "sanitized_report_scan_id": sanitized_report.scan_id,
            "sanitized_report_sha256": _canonical_json_hash(sanitized_report.to_dict()),
            "sanitized_manifest_sha256": sanitized_report.manifest_sha256,
        }
        promotion["promotion_sha256"] = _canonical_json_hash(promotion)
        promotion_path = self.workspace / "state" / "promotions" / f"{candidate}.json"
        if os.path.lexists(promotion_path):
            _remove_path(destination)
            raise IntegrityError("promotion receipt already exists; refusing to replace derivation evidence")
        _atomic_write_text(
            promotion_path,
            json.dumps(promotion, sort_keys=True, indent=2) + "\n",
            0o600,
        )
        return sanitized_report

    def approve(self, candidate: str, report: ScanReport, decision: ApprovalDecision) -> ApprovalRecord:
        """copy only SANITIZED bytes to APPROVED after an explicit decision."""

        source = self.stage_path(Stage.SANITIZED, candidate)
        if not decision.approved:
            raise ApprovalError("approval decision was explicitly negative")
        if not decision.actor.strip() or not decision.reason.strip():
            raise ApprovalError("an approving actor and non-empty reason are required")
        if report.stage is not Stage.SANITIZED or Path(report.root) != source:
            raise ApprovalError("approval accepts reports only for this candidate's SANITIZED stage")
        if not _constant_time_hex_equal(decision.expected_manifest_sha256, report.manifest_sha256):
            raise ApprovalError("the decision does not bind the report manifest")
        accepted = tuple(sorted(set(decision.accepted_findings)))
        unresolved = report.unresolved(accepted)
        if unresolved:
            raise ApprovalError(f"candidate has {len(unresolved)} unresolved finding(s)")
        if set(accepted) != {finding.id for finding in report.reviews}:
            raise ApprovalError("approval acceptance must name exactly the SANITIZED review findings")
        self.scanner.assert_unchanged(report)
        provenance = self._load_ingest_provenance(candidate)
        promotion = self._load_promotion_receipt(candidate)
        promotion_findings = tuple(str(row) for row in promotion["accepted_findings"])
        if (
            promotion["candidate"] != candidate
            or promotion["ingest_provenance_sha256"] != provenance["provenance_sha256"]
            or promotion["source_snapshot_manifest_sha256"] != provenance["source_snapshot_manifest_sha256"]
            or promotion["quarantine_manifest_sha256"] != provenance["quarantine_manifest_sha256"]
            or promotion["sanitized_manifest_sha256"] != report.manifest_sha256
        ):
            raise IntegrityError("promotion receipt does not form the recorded ingest derivation chain")

        destination = self.stage_path(Stage.APPROVED, candidate)
        _safe_copy_atomic(source, destination, inert=True)
        approved_manifest = self.scanner.current_manifest_sha256(destination)
        if approved_manifest != report.manifest_sha256:
            shutil.rmtree(destination, ignore_errors=True)
            raise IntegrityError("approved copy does not match the inspected SANITIZED manifest")

        # persist exactly the report whose canonical hash enters the approval
        # receipt. a prior promotion report may have another scan ID/time.
        self._write_report(candidate, Stage.SANITIZED, report)
        approval_payload = {
            "schema_version": SCHEMA_VERSION,
            "candidate": candidate,
            "actor": decision.actor.strip(),
            "reason": decision.reason.strip(),
            "approved_at": _now(),
            "source_stage": Stage.SANITIZED.value,
            "manifest_sha256": report.manifest_sha256,
            "approved_manifest_sha256": approved_manifest,
            "accepted_findings": list(accepted),
            "report_scan_id": report.scan_id,
            "report_sha256": _canonical_json_hash(report.to_dict()),
            "ingest_provenance_sha256": provenance["provenance_sha256"],
            "promotion_sha256": promotion["promotion_sha256"],
            "source_manifest_sha256": provenance["source_manifest_sha256"],
            "source_snapshot_manifest_sha256": provenance["source_snapshot_manifest_sha256"],
            "quarantine_manifest_sha256": promotion["quarantine_manifest_sha256"],
            "sanitized_manifest_sha256": promotion["sanitized_manifest_sha256"],
            "quarantine_report_scan_id": promotion["quarantine_report_scan_id"],
            "quarantine_report_sha256": promotion["quarantine_report_sha256"],
            "promotion_accepted_findings": list(promotion_findings),
        }
        approval_hash = _canonical_json_hash(approval_payload)
        record = ApprovalRecord(
            schema_version=SCHEMA_VERSION,
            candidate=candidate,
            actor=str(approval_payload["actor"]),
            reason=str(approval_payload["reason"]),
            approved_at=str(approval_payload["approved_at"]),
            source_stage=Stage.SANITIZED,
            manifest_sha256=report.manifest_sha256,
            approved_manifest_sha256=approved_manifest,
            accepted_findings=tuple(approval_payload["accepted_findings"]),  # type: ignore[arg-type]
            report_scan_id=report.scan_id,
            report_sha256=str(approval_payload["report_sha256"]),
            ingest_provenance_sha256=str(approval_payload["ingest_provenance_sha256"]),
            promotion_sha256=str(approval_payload["promotion_sha256"]),
            source_manifest_sha256=str(approval_payload["source_manifest_sha256"]),
            source_snapshot_manifest_sha256=str(approval_payload["source_snapshot_manifest_sha256"]),
            quarantine_manifest_sha256=str(approval_payload["quarantine_manifest_sha256"]),
            sanitized_manifest_sha256=str(approval_payload["sanitized_manifest_sha256"]),
            quarantine_report_scan_id=str(approval_payload["quarantine_report_scan_id"]),
            quarantine_report_sha256=str(approval_payload["quarantine_report_sha256"]),
            promotion_accepted_findings=promotion_findings,
            approval_sha256=approval_hash,
        )
        _atomic_write_text(
            self.workspace / "state" / "approvals" / f"{candidate}.json",
            json.dumps(record.to_dict(), sort_keys=True, indent=2) + "\n",
            0o600,
        )
        return record

    def _load_ingest_provenance(self, candidate: str) -> dict[str, object]:
        receipt = _load_self_hashed_receipt(
            self.workspace / "state" / f"{candidate}.provenance.json",
            hash_field="provenance_sha256",
            receipt_type="source-to-quarantine",
        )
        expected_fields = {
            "schema_version",
            "receipt_type",
            "candidate",
            "ingested_at",
            "original_source",
            "source_mount_enforced",
            "source_report_scan_id",
            "source_report_sha256",
            "source_manifest_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_scan_id",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
            "provenance_sha256",
        }
        required_hashes = (
            "provenance_sha256",
            "source_report_sha256",
            "source_manifest_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
        )
        if (
            set(receipt) != expected_fields
            or receipt.get("candidate") != candidate
            or any(
                not isinstance(receipt.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", str(receipt[key]))
                for key in required_hashes
            )
            or any(
                not isinstance(receipt.get(key), str) or not str(receipt[key]).strip()
                for key in (
                    "ingested_at",
                    "original_source",
                    "source_report_scan_id",
                    "quarantine_report_scan_id",
                )
            )
            or not isinstance(receipt.get("source_mount_enforced"), bool)
        ):
            raise IntegrityError("source-to-quarantine receipt is incomplete or belongs to another candidate")
        return receipt

    def _load_promotion_receipt(self, candidate: str) -> dict[str, object]:
        receipt = _load_self_hashed_receipt(
            self.workspace / "state" / "promotions" / f"{candidate}.json",
            hash_field="promotion_sha256",
            receipt_type="quarantine-to-sanitized",
        )
        expected_fields = {
            "schema_version",
            "receipt_type",
            "candidate",
            "promoted_at",
            "source_stage",
            "target_stage",
            "ingest_provenance_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_scan_id",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
            "accepted_findings",
            "sanitized_report_scan_id",
            "sanitized_report_sha256",
            "sanitized_manifest_sha256",
            "promotion_sha256",
        }
        required_hashes = (
            "promotion_sha256",
            "ingest_provenance_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
            "sanitized_report_sha256",
            "sanitized_manifest_sha256",
        )
        accepted = receipt.get("accepted_findings")
        if (
            set(receipt) != expected_fields
            or receipt.get("candidate") != candidate
            or receipt.get("source_stage") != Stage.QUARANTINE.value
            or receipt.get("target_stage") != Stage.SANITIZED.value
            or any(
                not isinstance(receipt.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", str(receipt[key]))
                for key in required_hashes
            )
            or any(
                not isinstance(receipt.get(key), str) or not str(receipt[key]).strip()
                for key in ("promoted_at", "quarantine_report_scan_id", "sanitized_report_scan_id")
            )
            or not isinstance(accepted, list)
            or any(not isinstance(row, str) or not row for row in accepted)
            or accepted != sorted(set(accepted))
        ):
            raise IntegrityError("quarantine-to-sanitized receipt is incomplete or invalid")
        return receipt

    def restore(
        self,
        candidate: str,
        destination: Path | str,
        approval: ApprovalRecord,
        *,
        confirmed: bool,
    ) -> Path:
        """restore an unchanged approved candidate without overwriting.

        a receipt is stored in RESTORED.  final placement policy and ownership
        mapping belong to the migration planner, not this content scanner.
        """

        if not confirmed:
            raise ApprovalError("restoration requires explicit confirmation")
        if approval.candidate != candidate:
            raise ApprovalError("approval belongs to another candidate")
        _require_root_private_restore_source(self.workspace)
        source = self.stage_path(Stage.APPROVED, candidate)
        current = self.scanner.current_manifest_sha256(source)
        if current != approval.approved_manifest_sha256:
            raise IntegrityError("APPROVED content changed after approval")
        destination = Path(destination).absolute()
        _safe_copy_atomic(source, destination, inert=False)
        restored_manifest = self.scanner.current_manifest_sha256(destination)
        if restored_manifest != current:
            _remove_path(destination)
            raise IntegrityError("restored copy does not match APPROVED content")
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "candidate": candidate,
            "restored_at": _now(),
            "destination": str(destination),
            "manifest_sha256": restored_manifest,
            "approval_sha256": approval.approval_sha256,
        }
        _atomic_write_text(
            self.stage_path(Stage.RESTORED, candidate).with_suffix(".json"),
            json.dumps(receipt, sort_keys=True, indent=2) + "\n",
            0o600,
        )
        return destination

    def _write_report(self, candidate: str, stage: Stage, report: ScanReport) -> None:
        report.write_json(self.workspace / "state" / "reports" / f"{candidate}.{stage.value.lower()}.json")

    def _validate_candidate(self, candidate: str) -> None:
        if not self._CANDIDATE_RE.fullmatch(candidate) or candidate in {".", ".."}:
            raise ValueError("candidate ID must be a safe ASCII identifier")


def _scanner_env() -> dict[str, str]:
    return {
        "PATH": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/nonexistent",
        "TZ": "UTC",
    }


def _sandbox_candidate_path(path: Path, root: Path) -> str:
    if path == root:
        return "/input"
    relative = path.relative_to(root)
    return str(PurePosixPath("/input", *relative.parts))


def _decode_mountinfo_path(value: str) -> str:
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    return re.sub(r"\\([0-7]{3})", lambda match: escapes.get(match.group(1), match.group(0)), value)


def _constant_time_hex_equal(observed: str, expected: str) -> bool:
    try:
        observed_bytes = bytes.fromhex(observed)
        expected_bytes = bytes.fromhex(expected)
    except ValueError:
        return False
    return (
        len(observed_bytes) == 32 and len(expected_bytes) == 32 and hmac.compare_digest(observed_bytes, expected_bytes)
    )


def _bounded_read(stream: BinaryIO, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = stream.read(min(_CHUNK_SIZE, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > limit:
        raise ValueError("bounded read limit exceeded")
    return data


def _directory_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_existing_directory_nofollow(path: Path) -> int:
    """open an absolute directory one component at a time without symlinks."""

    path = path.absolute()
    if not path.is_absolute() or ".." in path.parts:
        raise UnsafeInputError(f"unsafe source directory path: {path}")
    flags = _directory_open_flags()
    current = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise UnsafeInputError(f"unsafe source directory component: {component!r}")
            child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _open_existing_parent_nofollow(path: Path) -> tuple[int, str]:
    path = path.absolute()
    if not path.is_absolute() or ".." in path.parts:
        raise UnsafeInputError(f"unsafe source path: {path}")
    if path == Path("/"):
        return os.open("/", _directory_open_flags()), "."
    if not path.name or path.name in {".", ".."}:
        raise UnsafeInputError(f"unsafe source entry name: {path}")
    return _open_existing_directory_nofollow(path.parent), path.name


def _same_inode_and_type(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
    )


def _stable_source_stat(info: os.stat_result) -> tuple[int, ...]:
    """fields which must remain stable while an entry is snapshotted."""

    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_nlink,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _require_root_private_restore_source(workspace: Path) -> None:
    """for root restores, reject any workspace still writable by its source user."""

    if os.geteuid() != 0:
        return
    workspace_fd = _open_existing_directory_nofollow(workspace)
    approved_fd = -1
    try:
        root_info = os.fstat(workspace_fd)
        if root_info.st_uid != 0 or not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) & 0o077:
            raise UnsafeInputError("root restore requires a root-owned, root-exclusive private workspace snapshot")
        approved_fd = os.open(
            Stage.APPROVED.value,
            _directory_open_flags(),
            dir_fd=workspace_fd,
        )
        approved_info = os.fstat(approved_fd)
        if (
            approved_info.st_uid != 0
            or not stat.S_ISDIR(approved_info.st_mode)
            or stat.S_IMODE(approved_info.st_mode) & 0o077
        ):
            raise UnsafeInputError("root restore requires a root-owned, root-exclusive APPROVED snapshot anchor")
    finally:
        if approved_fd >= 0:
            os.close(approved_fd)
        os.close(workspace_fd)


def _safe_copy_atomic(
    source: Path,
    destination: Path,
    *,
    inert: bool,
    preserve_owner: bool = False,
    max_bytes: int | None = None,
) -> None:
    source = source.absolute()
    if not destination.is_absolute() or ".." in destination.parts or not destination.name:
        raise UnsafeInputError(f"restore destination must be a normalized absolute path: {destination}")
    if max_bytes is not None and max_bytes < 0:
        raise UnsafeInputError("copy byte limit must not be negative")
    source_parent_fd, source_name = _open_existing_parent_nofollow(source)
    parent_fd = -1
    temporary_name: str | None = None
    temporary_fd = -1
    staging: Path | None = None
    try:
        source_info = os.stat(
            source_name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
        parent_fd = _open_destination_parent(destination.parent)
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"refusing to overwrite existing destination: {destination}")
        proc_parent = Path(f"/proc/self/fd/{parent_fd}")
        if not proc_parent.is_dir():
            raise UnsafeInputError("/proc is required for fd-anchored restore staging")
        temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=proc_parent))
        temporary_name = temporary.name
        temporary_fd = os.open(
            temporary_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        staging = Path(f"/proc/self/fd/{temporary_fd}/payload")
        _safe_copy_entry(
            source_parent_fd,
            source_name,
            temporary_fd,
            "payload",
            inert=inert,
            hardlinks={},
            source_device=source_info.st_dev,
            destination_root_fd=temporary_fd,
            destination_relative="payload",
            source_display=str(source),
            preserve_owner=preserve_owner,
            budget=None if max_bytes is None else [max_bytes],
        )
        _rename_noreplace(temporary_fd, "payload", parent_fd, destination.name)
        staging = None
    except BaseException:
        if staging is not None:
            _remove_path(staging)
        raise
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name is not None:
            with contextlib.suppress(OSError):
                os.rmdir(temporary_name, dir_fd=parent_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(source_parent_fd)


def _open_destination_parent(parent: Path) -> int:
    """open/create an absolute directory path without following any symlink."""

    if not parent.is_absolute() or ".." in parent.parts:
        raise UnsafeInputError(f"unsafe restore destination parent: {parent}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    current = os.open("/", flags)
    try:
        for component in parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise UnsafeInputError(f"unsafe restore destination component: {component!r}")
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                try:
                    child = os.open(component, flags, dir_fd=current)
                except OSError as exc:
                    raise UnsafeInputError(
                        f"restore destination parent is not a stable real directory: {parent}"
                    ) from exc
            except OSError as exc:
                raise UnsafeInputError(
                    f"restore destination parent contains a symlink or non-directory: {parent}"
                ) from exc
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _rename_noreplace(source_fd: int, source_name: str, target_fd: int, target_name: str) -> None:
    """atomically publish a staged tree without ever replacing a target."""

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise UnsafeInputError("libc lacks renameat2; atomic no-overwrite restore is unavailable") from exc
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(source_fd, os.fsencode(source_name), target_fd, os.fsencode(target_name), 1) == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(f"refusing to overwrite existing destination entry: {target_name}")
    if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise UnsafeInputError("kernel/filesystem lacks atomic RENAME_NOREPLACE support")
    raise OSError(error, os.strerror(error), target_name)


def _safe_copy_entry(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
    *,
    inert: bool,
    hardlinks: dict[tuple[int, int], str],
    source_device: int,
    destination_root_fd: int,
    destination_relative: str,
    source_display: str,
    preserve_owner: bool,
    budget: list[int] | None,
) -> None:
    info = os.stat(
        source_name,
        dir_fd=source_parent_fd,
        follow_symlinks=False,
    )
    if info.st_dev != source_device:
        raise UnsafeInputError(f"refusing to copy across a nested filesystem boundary: {source_display}")
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(source_name, dir_fd=source_parent_fd)
        after = os.stat(
            source_name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
        if _stable_source_stat(info) != _stable_source_stat(after):
            raise IntegrityError(f"source symlink changed while copying: {source_display}")
        os.symlink(target, destination_name, dir_fd=destination_parent_fd)
        if preserve_owner:
            copied = os.stat(
                destination_name,
                dir_fd=destination_parent_fd,
                follow_symlinks=False,
            )
            if (copied.st_uid, copied.st_gid) != (info.st_uid, info.st_gid):
                os.chown(
                    destination_name,
                    info.st_uid,
                    info.st_gid,
                    dir_fd=destination_parent_fd,
                    follow_symlinks=False,
                )
        try:
            os.utime(
                destination_name,
                ns=(info.st_atime_ns, info.st_mtime_ns),
                dir_fd=destination_parent_fd,
                follow_symlinks=False,
            )
        except (NotImplementedError, OSError):
            pass
        return
    if stat.S_ISDIR(info.st_mode):
        source_fd = os.open(
            source_name,
            _directory_open_flags(),
            dir_fd=source_parent_fd,
        )
        destination_fd = -1
        try:
            opened = os.fstat(source_fd)
            if not _same_inode_and_type(info, opened):
                raise IntegrityError(f"source directory changed while opening: {source_display}")
            os.mkdir(
                destination_name,
                0o700,
                dir_fd=destination_parent_fd,
            )
            destination_fd = os.open(
                destination_name,
                _directory_open_flags(),
                dir_fd=destination_parent_fd,
            )
            names_before = sorted(os.listdir(source_fd), key=os.fsencode)
            for child_name in names_before:
                if child_name in {"", ".", ".."} or "/" in child_name or "\x00" in child_name:
                    raise IntegrityError(f"unsafe source directory entry while copying: {source_display}")
                child_relative = f"{destination_relative}/{child_name}"
                _safe_copy_entry(
                    source_fd,
                    child_name,
                    destination_fd,
                    child_name,
                    inert=inert,
                    hardlinks=hardlinks,
                    source_device=source_device,
                    destination_root_fd=destination_root_fd,
                    destination_relative=child_relative,
                    source_display=f"{source_display}/{child_name}",
                    preserve_owner=preserve_owner,
                    budget=budget,
                )
            names_after = sorted(os.listdir(source_fd), key=os.fsencode)
            after = os.fstat(source_fd)
            linked_after = os.stat(
                source_name,
                dir_fd=source_parent_fd,
                follow_symlinks=False,
            )
            if (
                names_before != names_after
                or _stable_source_stat(opened) != _stable_source_stat(after)
                or _stable_source_stat(info) != _stable_source_stat(linked_after)
            ):
                raise IntegrityError(f"source directory changed while copying: {source_display}")
            if preserve_owner:
                copied = os.fstat(destination_fd)
                if (copied.st_uid, copied.st_gid) != (info.st_uid, info.st_gid):
                    os.fchown(destination_fd, info.st_uid, info.st_gid)
            mode = stat.S_IMODE(info.st_mode) & ~0o7000
            if inert:
                mode = 0o700
            os.fchmod(destination_fd, mode)
            os.utime(
                destination_fd,
                ns=(info.st_atime_ns, info.st_mtime_ns),
            )
        finally:
            if destination_fd >= 0:
                os.close(destination_fd)
            os.close(source_fd)
        return
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeInputError(f"refusing to recreate special file: {source_display}")

    inode = (info.st_dev, info.st_ino)
    prior = hardlinks.get(inode)
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(
        source_name,
        source_flags,
        dir_fd=source_parent_fd,
    )
    destination_fd = -1
    try:
        opened = os.fstat(source_fd)
        if not _same_inode_and_type(info, opened) or not stat.S_ISREG(opened.st_mode):
            raise IntegrityError(f"source changed while copying: {source_display}")
        if prior is not None:
            os.link(
                prior,
                destination_name,
                src_dir_fd=destination_root_fd,
                dst_dir_fd=destination_parent_fd,
                follow_symlinks=False,
            )
            destination_fd = os.open(
                destination_name,
                source_flags,
                dir_fd=destination_parent_fd,
            )
        else:
            if budget is not None:
                if opened.st_size > budget[0]:
                    raise UnsafeInputError(f"copy byte limit exceeded by source file: {source_display}")
                budget[0] -= opened.st_size
            destination_fd = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=destination_parent_fd,
            )
            remaining = opened.st_size
            while remaining:
                chunk = os.read(source_fd, min(_CHUNK_SIZE, remaining))
                if not chunk:
                    raise IntegrityError(f"source was truncated while copying: {source_display}")
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise OSError("short write while copying")
                    view = view[written:]
                remaining -= len(chunk)
            if os.read(source_fd, 1):
                raise IntegrityError(f"source grew while copying: {source_display}")
            os.fsync(destination_fd)

        after = os.fstat(source_fd)
        linked_after = os.stat(
            source_name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
        if _stable_source_stat(opened) != _stable_source_stat(after) or _stable_source_stat(
            info
        ) != _stable_source_stat(linked_after):
            raise IntegrityError(f"source changed while copying: {source_display}")
        if preserve_owner:
            copied = os.fstat(destination_fd)
            if (copied.st_uid, copied.st_gid) != (info.st_uid, info.st_gid):
                os.fchown(destination_fd, info.st_uid, info.st_gid)
        mode = stat.S_IMODE(info.st_mode) & ~0o7000
        if inert:
            mode = 0o600
        os.fchmod(destination_fd, mode)
        os.utime(
            destination_fd,
            ns=(info.st_atime_ns, info.st_mtime_ns),
        )
        if prior is None:
            hardlinks[inode] = destination_relative
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def _remove_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def _make_tree_read_only(root: Path) -> None:
    """remove write bits without following links; the manifest detects chmod-back."""

    paths: list[Path] = []
    stack = [root]
    while stack:
        path = stack.pop()
        paths.append(path)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as iterator:
                stack.extend(Path(entry.path) for entry in iterator)
    for path in sorted(paths, key=lambda item: len(item.parts), reverse=True):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        os.chmod(path, stat.S_IMODE(info.st_mode) & ~0o222, follow_symlinks=False)


__all__ = [
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalRecord",
    "ExternalScanResult",
    "FileRecord",
    "Finding",
    "IngestResult",
    "IntegrityError",
    "ScanPolicy",
    "ScanReport",
    "ScannerError",
    "Severity",
    "Stage",
    "ToolEvidence",
    "UnsafeInputError",
    "ZeroTrustPipeline",
    "ZeroTrustScanner",
]
