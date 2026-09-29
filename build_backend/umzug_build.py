"""tiny offline PEP 517 backend.

the project intentionally has no build dependency.  the backend creates a
standards-compliant pure-python wheel using only the standard library.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import os
from pathlib import Path
import stat
import zipfile

NAME = "umzug_toolkit"
VERSION = "0.2.0rc1"


def _dist_info() -> str:
    return f"{NAME}-{VERSION}.dist-info"


def get_requires_for_build_wheel(config_settings=None):  # noqa: ANN001
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):  # noqa: ANN001
    target = Path(metadata_directory) / _dist_info()
    target.mkdir(parents=True, exist_ok=True)
    (target / "METADATA").write_text(_metadata(), encoding="utf-8")
    (target / "WHEEL").write_text(_wheel(), encoding="utf-8")
    (target / "entry_points.txt").write_text(_entry_points(), encoding="utf-8")
    return target.name


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):  # noqa: ANN001
    root = Path(__file__).resolve().parents[1]
    wheel_name = f"{NAME}-{VERSION}-py3-none-any.whl"
    wheel_path = Path(wheel_directory) / wheel_name
    records: list[tuple[str, str, str]] = []
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    # ZIP cannot represent dates before 1980.
    import datetime

    dt = datetime.datetime.fromtimestamp(max(epoch, 315532800), datetime.UTC)
    zip_dt = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    def add(zf: zipfile.ZipFile, name: str, data: bytes, *, mode: int = 0o644) -> None:
        info = zipfile.ZipInfo(name, zip_dt)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | mode) << 16
        zf.writestr(info, data)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        records.append((name, f"sha256={digest}", str(len(data))))

    with zipfile.ZipFile(wheel_path, "w") as zf:
        for path in sorted((root / "src" / "umzug").glob("*.py")):
            add(zf, f"umzug/{path.name}", path.read_bytes())
        add(
            zf,
            f"{NAME}-{VERSION}.data/scripts/umzug-setup-root",
            (root / "scripts" / "umzug-setup-root").read_bytes(),
            mode=0o755,
        )
        info = _dist_info()
        add(zf, f"{info}/METADATA", _metadata().encode())
        add(zf, f"{info}/WHEEL", _wheel().encode())
        add(zf, f"{info}/entry_points.txt", _entry_points().encode())
        record_name = f"{info}/RECORD"
        records.append((record_name, "", ""))
        rows = [",".join(row) for row in records]
        add(zf, record_name, ("\n".join(rows) + "\n").encode())
    return wheel_name


def _metadata() -> str:
    return (
        "Metadata-Version: 2.1\n"
        f"Name: umzug-toolkit\nVersion: {VERSION}\n"
        "Summary: Offline-first zero-trust Linux migration toolkit\n"
        "Requires-Python: >=3.11\nLicense: GPL-3.0-or-later\n"
    )


def _wheel() -> str:
    return "Wheel-Version: 1.0\nGenerator: umzug_build\nRoot-Is-Purelib: true\nTag: py3-none-any\n"


def _entry_points() -> str:
    # privileged setup must use the wheel-shipped isolated shell wrapper.  a
    # generated python console script imports before setup_cli can check its
    # root-owned runtime and is therefore intentionally not exposed here.
    return "[console_scripts]\numzug-pack=umzug.pack_cli:main\n"
