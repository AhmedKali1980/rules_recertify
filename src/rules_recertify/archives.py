"""Verified, atomic tar.gz storage for completed raw collection runs."""
from __future__ import annotations

import hashlib
import shutil
import tarfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import List


@dataclass(frozen=True)
class PreparedArchive:
    path: Path
    sha256: str
    size_bytes: int


def prepare_run_archive(run_dir: Path, archives_dir: Path) -> PreparedArchive:
    """Create, verify, and atomically publish one run archive without deleting its source."""
    if not run_dir.is_dir() or not (run_dir / "manifest.json").is_file():
        raise RuntimeError(f"Run directory has no manifest: {run_dir}")
    archives_dir.mkdir(parents=True, exist_ok=True)
    target = archives_dir / f"{run_dir.name}.tar.gz"
    temporary = archives_dir / f".{run_dir.name}.tar.gz.tmp"
    if target.exists():
        raise RuntimeError(f"Archive already exists: {target}")
    temporary.unlink(missing_ok=True)
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            archive.add(run_dir, arcname=run_dir.name, recursive=True)
        _validate_archive(temporary, run_dir.name)
        digest = _sha256(temporary)
        size_bytes = temporary.stat().st_size
        temporary.replace(target)
        return PreparedArchive(target, digest, size_bytes)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def discard_prepared_archive(archive: PreparedArchive) -> None:
    archive.path.unlink(missing_ok=True)


def restore_archive(archive_path: Path, target_root: Path) -> Path:
    """Safely restore one verified archive through a same-filesystem staging directory."""
    run_id = _archive_run_id(archive_path)
    _validate_archive(archive_path, run_id)
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / run_id
    temporary = target_root / f".{run_id}.restore.tmp"
    if target.exists() or temporary.exists():
        raise RuntimeError(f"Restore destination already exists for {run_id}")
    temporary.mkdir()
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                relative = _safe_member(member, run_id)
                if not relative.parts:
                    continue
                destination = temporary.joinpath(*relative.parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise RuntimeError(f"Cannot read archive member: {member.name}")
                    with source, destination.open("wb") as output:
                        shutil.copyfileobj(source, output)
                else:
                    raise RuntimeError(f"Unsupported archive member type: {member.name}")
        if not (temporary / "manifest.json").is_file():
            raise RuntimeError("Restored archive has no manifest")
        temporary.replace(target)
        return target
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def purge_expired_archives(db: object, as_of: date) -> List[str]:
    """Delete expired, recorded archives and their SQLite metadata."""
    removed: List[str] = []
    with db.connect() as connection:
        rows = connection.execute(
            """SELECT run_id,archive_path FROM run_archives
            WHERE retained_until IS NOT NULL AND retained_until<?""",
            (as_of.isoformat(),),
        ).fetchall()
        for row in rows:
            path = Path(str(row["archive_path"]))
            path.unlink(missing_ok=True)
            connection.execute("DELETE FROM run_archives WHERE run_id=?", (row["run_id"],))
            removed.append(str(row["run_id"]))
    return removed


def _validate_archive(path: Path, run_id: str) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise RuntimeError(f"Archive is empty: {path}")
        relative_files = []
        for member in members:
            relative = _safe_member(member, run_id)
            if member.isfile():
                relative_files.append(relative.as_posix())
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(f"Cannot read archive member: {member.name}")
                with source:
                    while source.read(1024 * 1024):
                        pass
        if "manifest.json" not in relative_files:
            raise RuntimeError(f"Archive has no manifest: {path}")


def _safe_member(member: tarfile.TarInfo, run_id: str) -> PurePosixPath:
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != run_id:
        raise RuntimeError(f"Unsafe archive member: {member.name}")
    if member.issym() or member.islnk():
        raise RuntimeError(f"Archive links are not supported: {member.name}")
    return PurePosixPath(*path.parts[1:])


def _archive_run_id(path: Path) -> str:
    suffix = ".tar.gz"
    if not path.name.endswith(suffix):
        raise ValueError("archive name must end with .tar.gz")
    run_id = path.name[:-len(suffix)]
    if not run_id:
        raise ValueError("archive name has no run identifier")
    return run_id


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
