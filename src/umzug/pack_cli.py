from __future__ import annotations

import argparse
from collections import Counter
import contextlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import tomllib
from typing import Any

from .inventory import INVENTORY_SECTIONS, collect_inventory
from .limits import MAX_CANDIDATE_OBJECTS, MAX_SIGNED_METADATA_BYTES
from .manifest import (
    DEFAULT_EXCLUDES,
    SENSITIVE_EXCLUDES,
    Selection,
    assemble_bundle,
    build_source_tar,
    create_manifest,
    encrypt_bundle,
    generate_signing_key,
    preview_selections,
    preview_captured_source,
    public_key_fingerprint,
    public_key_for,
    sensitive_metadata_candidates,
    sign_manifest,
    verify_source_tar_manifest,
)
from .transport import split_file
from .util import (
    AuditLog,
    UmzugError,
    atomic_write,
    canonical_json,
    contained,
    open_directory_chain,
    rename_noreplace_at,
    sha256_file,
    terminal_safe,
    which,
)


CATEGORY_CANDIDATES = {
    "projects": ["~/Projects", "~/projects", "~/src", "~/code", "~/workspace"],
    "dotfiles": ["~/.config", "~/.local/share", "~/.profile", "~/.bashrc", "~/.zshrc"],
    "git": ["~/.gitconfig", "~/.config/git"],
    "services": ["~/.config/systemd/user", "/etc/systemd/system", "/usr/local/bin", "~/bin"],
    "automation": ["/etc/crontab", "/etc/cron.d", "~/.config/systemd/user"],
    "ssh-client": ["~/.ssh/config", "~/.ssh/known_hosts"],
    "network": ["/etc/NetworkManager/system-connections", "/etc/systemd/network", "/etc/nftables.conf"],
    "appearance": ["~/.local/share/fonts", "~/.fonts", "~/.themes", "~/.icons"],
    "distribution": ["/etc/portage", "/etc/nixos", "/etc/pacman.conf", "/etc/apt/sources.list.d"],
}
MAX_SIGNING_KEY_BYTES = 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pack",
        description="Create a signed, optionally encrypted, untrusted migration bundle.",
    )
    parser.add_argument("--output", type=Path, help="destination bundle path")
    parser.add_argument("--include", action="append", default=[], metavar="[CATEGORY=]PATH")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument(
        "--inventory",
        action="append",
        choices=INVENTORY_SECTIONS,
        default=[],
        help="explicitly include one metadata inventory section (repeatable; default: none)",
    )
    parser.add_argument("--config", type=Path, help="TOML configuration for non-interactive use")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--generate-signing-key", type=Path)
    parser.add_argument(
        "--encrypt",
        choices=("none", "age-recipient", "age-passphrase", "gpg-symmetric"),
        default="none",
    )
    parser.add_argument("--recipient", help="age recipient (public, safe for config files)")
    parser.add_argument("--include-sensitive", action="store_true")
    parser.add_argument("--acknowledge-sensitive-risk", action="store_true")
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--split-size", type=int, help="split final file into byte-sized transport chunks")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--json", action="store_true", help="print preview/result as JSON")
    parser.add_argument("--expert", action="store_true", help="show complete exclusion and finding lists")
    return parser


def _load_config(path: Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise UmzugError(f"cannot read configuration: {exc}") from exc
    pack = value.get("pack")
    if not isinstance(pack, dict):
        raise UmzugError("configuration needs a [pack] table")
    return pack


def _apply_config(args: argparse.Namespace, config: dict[str, Any]) -> None:
    scalar = {
        "output": Path,
        "signing_key": Path,
        "generate_signing_key": Path,
        "encrypt": str,
        "recipient": str,
        "include_sensitive": bool,
        "acknowledge_sensitive_risk": bool,
        "source_date_epoch": int,
        "split_size": int,
    }
    allowed = set(scalar) | {"include", "exclude", "inventory"}
    unknown = sorted(set(config) - allowed)
    if unknown:
        raise UmzugError(f"unknown pack configuration keys: {', '.join(unknown)}")
    for key, converter in scalar.items():
        if key in config and getattr(args, key, None) in (None, False, "none"):
            value = config[key]
            if converter is Path:
                if not isinstance(value, str):
                    raise UmzugError(f"pack.{key} must be a path string")
                converted: Any = Path(value)
            elif converter is bool:
                if not isinstance(value, bool):
                    raise UmzugError(f"pack.{key} must be boolean")
                converted = value
            elif converter is int:
                if not isinstance(value, int) or isinstance(value, bool):
                    raise UmzugError(f"pack.{key} must be an integer")
                converted = value
            else:
                if not isinstance(value, str):
                    raise UmzugError(f"pack.{key} must be a string")
                converted = value
            setattr(args, key, converted)
    if "include" in config and not isinstance(config["include"], list):
        raise UmzugError("pack.include must be an array of tables")
    for row in config.get("include", []):
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise UmzugError("each [[pack.include]] needs path and optional category")
        if "category" in row and not isinstance(row["category"], str):
            raise UmzugError("pack.include.category must be a string")
    if not args.include:
        for row in config.get("include", []):
            args.include.append(f"{row.get('category', 'custom')}={row['path']}")
    if isinstance(config.get("exclude"), list):
        if any(not isinstance(item, str) for item in config["exclude"]):
            raise UmzugError("pack.exclude entries must be strings")
        args.exclude.extend(config["exclude"])
    elif "exclude" in config:
        raise UmzugError("pack.exclude must be a list")
    if "inventory" in config:
        inventory = config["inventory"]
        if not isinstance(inventory, list) or any(
            not isinstance(item, str) or item not in INVENTORY_SECTIONS for item in inventory
        ):
            raise UmzugError("pack.inventory must contain only: " + ", ".join(INVENTORY_SECTIONS))
        if not args.inventory:
            args.inventory.extend(inventory)


def _parse_selection(raw: str) -> Selection:
    if "=" in raw:
        category, value = raw.split("=", 1)
    else:
        category, value = "custom", raw
    if not category or not value or "\x00" in value:
        raise UmzugError(f"invalid --include value: {raw!r}")
    return Selection(Path(value).expanduser(), category)


def _interactive_selections() -> list[Selection]:
    if not sys.stdin.isatty():
        raise UmzugError("interactive selection requires a TTY; use --config --non-interactive")
    print("Alle Quelldaten gelten als potenziell kompromittiert. Nichts wird später automatisch freigegeben.\n")
    selected: list[Selection] = []
    for category, candidates in CATEGORY_CANDIDATES.items():
        existing = [Path(value).expanduser() for value in candidates if os.path.lexists(Path(value).expanduser())]
        if not existing:
            continue
        answer = input(f"{category}: {', '.join(map(str, existing))} aufnehmen? [y/N] ").strip().lower()
        if answer in {"y", "yes", "j", "ja"}:
            selected.extend(Selection(path, category) for path in existing)
    while True:
        value = input("Weiteren Pfad aufnehmen (leer = fertig): ").strip()
        if not value:
            return selected
        category = input("Kategorie [custom]: ").strip() or "custom"
        selected.append(Selection(Path(value).expanduser(), category))


def _interactive_inventory() -> list[str]:
    selected: list[str] = []
    print("\nOptionale Metadaten-Inventare (standardmäßig keines):")
    for section in INVENTORY_SECTIONS:
        if input(f"Inventar {section!r} ins Manifest aufnehmen? [y/N] ").strip().lower() in {
            "y",
            "yes",
            "j",
            "ja",
        }:
            selected.append(section)
    return selected


def _confirm(prompt: str, phrase: str | None = None) -> None:
    if not sys.stdin.isatty():
        raise UmzugError("confirmation requires a TTY")
    if phrase:
        answer = input(f"{prompt}\nZum Bestätigen exakt {phrase!r} eingeben: ")
        if answer != phrase:
            raise UmzugError("confirmation declined")
    else:
        if input(f"{prompt} [y/N] ").strip().lower() not in {"y", "yes", "j", "ja"}:
            raise UmzugError("confirmation declined")


def _snapshot_signing_key(source: Path, destination: Path) -> tuple[int, int]:
    """copy one stable, non-symlink private-key inode into the private workdir."""
    source_fd = -1
    output_fd = -1
    try:
        source_fd = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError("signing private key must be a regular, non-symlink file")
        if stat.S_IMODE(before.st_mode) & 0o077:
            raise UmzugError("signing private key permissions must be 0600 or stricter")
        if before.st_size <= 0 or before.st_size > MAX_SIGNING_KEY_BYTES:
            raise UmzugError("signing private key has an unsafe size")
        output_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        copied = 0
        with (
            os.fdopen(source_fd, "rb", buffering=0) as input_file,
            os.fdopen(output_fd, "wb", buffering=0) as output_file,
        ):
            source_fd = -1
            output_fd = -1
            while chunk := input_file.read(min(64 * 1024, MAX_SIGNING_KEY_BYTES + 1 - copied)):
                copied += len(chunk)
                if copied > MAX_SIGNING_KEY_BYTES:
                    raise UmzugError("signing private key grew beyond the safety limit")
                output_file.write(chunk)
            after = os.fstat(input_file.fileno())
            output_file.flush()
            os.fsync(output_file.fileno())
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
        if copied != before.st_size or any(getattr(before, name) != getattr(after, name) for name in stable_fields):
            raise UmzugError("signing private key changed while it was snapshotted")
        return before.st_dev, before.st_ino
    except OSError as exc:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise UmzugError("cannot safely snapshot the signing private key") from exc
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if output_fd >= 0:
            os.close(output_fd)


def _human_preview(preview: dict[str, Any], *, expert: bool = False) -> None:
    print("\nVorschau")
    print(f"  Dateien: {preview['files']}, Verzeichnisse: {preview['directories']}, Symlinks: {preview['symlinks']}")
    print(f"  Nutzdaten: {preview['bytes']} Bytes")
    print(f"  Ausgeschlossen: {len(preview['excluded'])}, Spezialdateien: {len(preview['special'])}")
    print(
        f"  Potenziell sensible Inhalte: {len(preview['sensitive_candidates'])}; nur teilweise geprüft: {len(preview['content_scan_incomplete'])}"
    )
    for row in preview["selections"]:
        print(f"  - [{terminal_safe(row['category'])}] {terminal_safe(row['path'])}")
    inventory = preview.get("inventory", {})
    if inventory:
        print("  Explizit gewähltes Metadaten-Inventar: " + ", ".join(sorted(inventory)))
        if expert:
            print(json.dumps(inventory, indent=2, sort_keys=True, ensure_ascii=False))
    if preview["unreadable"]:
        print("  Nicht lesbar/fehlend:")
        for row in preview["unreadable"][:20]:
            print(f"    - {terminal_safe(row['path'])}: {terminal_safe(row['reason'])}")
    if preview["special"]:
        print("  Spezialdateien werden nicht archiviert:")
        for path in preview["special"] if expert else preview["special"][:20]:
            print(f"    - {terminal_safe(path)}")
    if expert and preview["excluded"]:
        print("  Effektiv ausgeschlossen:")
        for path in preview["excluded"]:
            print(f"    - {terminal_safe(path)}")
    if expert and preview["sensitive_candidates"]:
        print("  Secret-Heuristiktreffer:")
        for row in preview["sensitive_candidates"]:
            print(f"    - {terminal_safe(row['path'])}: {terminal_safe(','.join(row['detectors']))}")


def _enforce_preview_policy(preview: dict[str, Any], *, include_sensitive: bool) -> None:
    if preview["unreadable"]:
        raise UmzugError("selection contains missing or unreadable paths; correct it before packing")
    if preview["special"]:
        raise UmzugError("selection contains device/FIFO/socket/special files; exclude them explicitly before packing")
    if preview["sensitive_candidates"] and not include_sensitive:
        paths = ", ".join(row["path"] for row in preview["sensitive_candidates"][:10])
        raise UmzugError(
            f"potential secret material detected; exclude these paths or use encrypted --include-sensitive: {paths}"
        )
    if preview["content_scan_incomplete"] and not include_sensitive:
        paths = ", ".join(preview["content_scan_incomplete"][:10])
        raise UmzugError(
            "secret preview was incomplete for one or more large files; exclude them or use the "
            f"explicit encrypted sensitive-data workflow: {paths}"
        )


def _publish_output(staged: Path, output_parent_fd: int, output_name: str) -> None:
    """publish a completed artifact atomically without following/clobbering targets."""

    staged_parent_fd = os.open(
        staged.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        rename_noreplace_at(staged_parent_fd, staged.name, output_parent_fd, output_name)
    except FileExistsError as exc:
        raise UmzugError(f"refusing to overwrite existing output: {output_name}") from exc
    finally:
        os.close(staged_parent_fd)


def _enforce_capture_limits(entries: list[dict[str, Any]], manifest_data: bytes | None = None) -> None:
    counts = Counter(str(row.get("source_selection", "")) for row in entries)
    oversized = sorted(name for name, count in counts.items() if count > MAX_CANDIDATE_OBJECTS)
    if oversized:
        raise UmzugError(
            f"a candidate exceeds the {MAX_CANDIDATE_OBJECTS}-object scanner limit; "
            "split the selection before packing: " + ", ".join(oversized)
        )
    if manifest_data is not None and len(manifest_data) > MAX_SIGNED_METADATA_BYTES:
        raise UmzugError(
            f"signed manifest exceeds the {MAX_SIGNED_METADATA_BYTES}-byte ingest limit; split the migration package"
        )


def execute(args: argparse.Namespace) -> dict[str, Any]:
    if args.config:
        _apply_config(args, _load_config(args.config))
    if args.encrypt not in {"none", "age-recipient", "age-passphrase", "gpg-symmetric"}:
        raise UmzugError("invalid pack encryption mode")
    if args.encrypt == "age-recipient" and not args.recipient:
        raise UmzugError("age recipient encryption requires a recipient")
    if args.source_date_epoch is not None and args.source_date_epoch < 0:
        raise UmzugError("--source-date-epoch must be non-negative")
    if args.split_size is not None and args.split_size < 1024 * 1024:
        raise UmzugError("--split-size must be at least 1 MiB")
    log = AuditLog(args.log)
    selections = [_parse_selection(value) for value in args.include]
    if not selections and not args.non_interactive:
        selections = _interactive_selections()
    if not selections:
        raise UmzugError("no source paths selected")
    if not args.non_interactive and not args.inventory:
        args.inventory = _interactive_inventory()
    inventory = collect_inventory(args.inventory)
    exclusions = tuple(DEFAULT_EXCLUDES) + tuple(args.exclude)
    preview = preview_selections(selections, exclusions, include_sensitive=args.include_sensitive)
    preview["inventory"] = inventory
    preview["sensitive_candidates"].extend(
        sensitive_metadata_candidates(
            selections=preview["selections"],
            inventory=inventory,
            exclusions=list(exclusions),
        )
    )
    log.event("pack.preview", counts={key: preview[key] for key in ("files", "directories", "symlinks", "bytes")})
    if not args.json:
        _human_preview(preview, expert=args.expert)
    _enforce_preview_policy(preview, include_sensitive=args.include_sensitive)
    if args.include_sensitive:
        if args.encrypt == "none":
            raise UmzugError("sensitive-data override is permitted only with full-bundle encryption")
        if not args.acknowledge_sensitive_risk:
            if args.non_interactive:
                raise UmzugError("non-interactive sensitive inclusion requires acknowledge_sensitive_risk=true")
            _confirm(
                "Private keys, tokens, passwords, and VPN credentials remain excluded by default. "
                "This override can expose secrets to the quarantine environment.",
                "SENSITIVE DATEN VERSCHLUESSELT AUFNEHMEN",
            )
    if args.dry_run:
        return {
            "status": "dry-run",
            "preview": preview,
            "effective_sensitive_excludes": [] if args.include_sensitive else list(SENSITIVE_EXCLUDES),
        }
    if not args.output:
        raise UmzugError("--output is required")
    output = args.output.expanduser().absolute()
    for selection in selections:
        selected = selection.path.expanduser().absolute()
        if selected.is_dir() and contained(selected, output):
            raise UmzugError("output must not be inside a selected source directory")
    if args.non_interactive and args.include_sensitive and not args.acknowledge_sensitive_risk:
        raise UmzugError("non-interactive sensitive inclusion requires acknowledge_sensitive_risk=true")

    signing_key = args.signing_key or args.generate_signing_key
    if signing_key is None:
        raise UmzugError("a signing key is mandatory (--signing-key or --generate-signing-key)")
    signing_key = signing_key.expanduser().absolute()
    for selection in selections:
        selected = selection.path.expanduser().absolute()
        lexically_below = False
        if selected.is_dir():
            try:
                signing_key.relative_to(selected)
                lexically_below = True
            except ValueError:
                pass
        if (selected.is_dir() and contained(selected, signing_key)) or selected == signing_key or lexically_below:
            raise UmzugError("the signing private key must not be part of the selected source data")
    if args.generate_signing_key:
        generate_signing_key(signing_key)
    if not signing_key.is_file():
        raise UmzugError(f"signing key not found: {signing_key}")
    if args.encrypt.startswith("age") and which("age") is None:
        raise UmzugError("age encryption selected but age is not installed")
    if args.encrypt.startswith("gpg") and which("gpg") is None:
        raise UmzugError("GnuPG encryption selected but gpg is not installed")

    try:
        output_parent_fd = open_directory_chain(output.parent, create=True)
    except OSError as exc:
        raise UmzugError("output parent cannot be opened without following symlinks") from exc
    try:
        try:
            os.stat(output.name, dir_fd=output_parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise UmzugError(f"refusing to overwrite existing output: {output}")
        temp_parent = Path("/proc/self/fd") / str(output_parent_fd)
        if not Path("/proc/self/fd").is_dir():
            raise UmzugError("/proc is required for fd-anchored package creation")
        with tempfile.TemporaryDirectory(prefix="umzug-pack-", dir=temp_parent) as tmp_name:
            tmp = Path(tmp_name)
            os.chmod(tmp, 0o700)
            stable_signing_key = tmp / "signing-private.pem"
            signing_key_inode = _snapshot_signing_key(signing_key, stable_signing_key)
            source_tar = tmp / "SOURCE.tar"
            entries, selection_rows, warnings = build_source_tar(
                source_tar,
                selections,
                exclusions,
                include_sensitive=args.include_sensitive,
                source_date_epoch=args.source_date_epoch,
                forbidden_regular_inodes={signing_key_inode},
            )
            if warnings:
                raise UmzugError(
                    "source changed or could not be captured completely; no package was created: "
                    + "; ".join(warnings[:20])
                )
            _enforce_capture_limits(entries)
            # detect source races or tar/manifest metadata inconsistencies before
            # any signature can turn the snapshot into a transport artifact.
            verify_source_tar_manifest(source_tar, {"entries": entries})
            captured_preview = preview_captured_source(
                source_tar,
                entries,
                selection_rows,
                excluded=preview["excluded"],
                inventory=inventory,
            )
            _enforce_preview_policy(captured_preview, include_sensitive=args.include_sensitive)
            preview = captured_preview
            log.event(
                "pack.captured_preview",
                counts={key: preview[key] for key in ("files", "directories", "symlinks", "bytes")},
            )
            if not args.json:
                print("\nUnveränderlicher, tatsächlich zu signierender Snapshot:")
                _human_preview(preview, expert=args.expert)
            if not args.non_interactive:
                _confirm("Signiertes Migrationspaket mit exakt diesem Snapshot erstellen?")
            manifest = create_manifest(
                source_tar,
                entries,
                selection_rows,
                exclusions,
                warnings,
                inventory,
                source_date_epoch=args.source_date_epoch,
            )
            manifest_path = tmp / "manifest.json"
            signature_path = tmp / "manifest.sig"
            public_key = tmp / "signing-public.pem"
            manifest_data = canonical_json(manifest)
            _enforce_capture_limits(entries, manifest_data)
            atomic_write(manifest_path, manifest_data, 0o600)
            public_key_for(stable_signing_key, public_key, pass_fds=(output_parent_fd,))
            sign_manifest(
                manifest_path,
                stable_signing_key,
                signature_path,
                pass_fds=(output_parent_fd,),
            )
            fingerprint = public_key_fingerprint(public_key, pass_fds=(output_parent_fd,))
            plain_bundle = tmp / "bundle.tar"
            assemble_bundle(
                plain_bundle,
                manifest_path,
                signature_path,
                public_key,
                source_tar,
                source_date_epoch=args.source_date_epoch,
            )
            if args.encrypt == "none":
                staged_output = plain_bundle
            else:
                staged_output = tmp / "bundle.encrypted"
                encrypt_bundle(
                    plain_bundle,
                    staged_output,
                    args.encrypt,
                    args.recipient,
                    pass_fds=(output_parent_fd,),
                )
            os.chmod(staged_output, 0o600)
            staged_sha256 = sha256_file(staged_output)
            staged_size = staged_output.stat().st_size
            _publish_output(staged_output, output_parent_fd, output.name)
    finally:
        os.close(output_parent_fd)
    result: dict[str, Any] = {
        "status": "created",
        "output": str(output),
        "sha256": staged_sha256,
        "size": staged_size,
        "signing_key_fingerprint": fingerprint,
        "preview": preview,
        "effective_sensitive_excludes": [] if args.include_sensitive else list(SENSITIVE_EXCLUDES),
        "warning": "Record and verify this fingerprint through an independent channel. A bundled key alone is not trust.",
    }
    if args.split_size:
        result["parts_index"] = str(split_file(output, args.split_size))
    log.event("pack.created", output=str(output), sha256=result["sha256"], fingerprint=fingerprint)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = execute(args)
    except (UmzugError, OSError) as exc:
        print(f"pack: error: {terminal_safe(exc)}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        if result.get("status") == "created":
            print(f"\nPaket erstellt: {terminal_safe(result['output'])}")
            print(f"SHA-256: {result['sha256']}")
            print(f"Ed25519-Schlüsselfingerabdruck: {result['signing_key_fingerprint']}")
            print("Fingerabdruck getrennt vom Datenträger aufbewahren und beim Zielsystem prüfen.")
        else:
            print("Dry-Run abgeschlossen; es wurden keine Dateien geschrieben.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
