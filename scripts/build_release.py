#!/usr/bin/env python3
"""Build and compare release-candidate artifacts from bounded source inputs."""

from __future__ import annotations

import argparse
import ast
import contextlib
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "erp_security_evidence_workbench"
DISTRIBUTION = "erp-security-evidence-workbench"
NORMALIZED_DISTRIBUTION = "erp_security_evidence_workbench"
BUILD_FILES = ("LICENSE", "MANIFEST.in", "README.md", "THIRD_PARTY_NOTICES.md", "pyproject.toml")
COMMAND_TIMEOUT_SECONDS = 120
DEFAULT_SOURCE_DATE_EPOCH = 1788307200
EXPECTED_BUILD_TOOLS = {
    "build": "1.6.0",
    "setuptools": "84.0.0",
    "wheel": "0.48.0",
}

_BUILD_ENVIRONMENT_PROGRAM = r"""
import importlib.metadata
import json
import platform

payload = {
    "implementation": platform.python_implementation(),
    "machine": platform.machine(),
    "operating_system": platform.system(),
    "operating_system_release": platform.release(),
    "python": platform.python_version(),
    "tools": {
        name: importlib.metadata.version(name)
        for name in ("build", "setuptools", "wheel")
    },
}
print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
""".strip()


class BuildError(RuntimeError):
    """A release build could not be completed safely."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _package_version() -> str:
    init_path = PACKAGE_ROOT / "__init__.py"
    module = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    for statement in module.body:
        if (
            isinstance(statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in statement.targets
            )
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            return statement.value.value
    raise BuildError("package version is not a static string")


def _preflight_output(path: Path) -> None:
    if path.name in {"", ".", ".."}:
        raise BuildError("output directory must be new or empty")
    try:
        parent_metadata = path.parent.lstat()
    except OSError as exc:
        raise BuildError("output parent directory does not exist") from exc
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise BuildError("output parent directory must be a real directory")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BuildError("output directory could not be inspected") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise BuildError("output directory must not be a symbolic link")
    if not stat.S_ISDIR(metadata.st_mode) or any(path.iterdir()):
        raise BuildError("output directory must be new or empty")


def _copy_regular_file(source: Path, destination: Path) -> None:
    source_stat = source.lstat()
    if not stat.S_ISREG(source_stat.st_mode):
        raise BuildError(f"build input is not a regular file: {source.relative_to(PROJECT_ROOT)}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def _source_entries(destination: Path, copied_paths: list[str]) -> tuple[dict[str, object], ...]:
    entries: list[dict[str, object]] = []
    for relative in sorted(copied_paths):
        content = (destination / relative).read_bytes()
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    return tuple(entries)


def _source_tree_digest(entries: tuple[dict[str, object], ...]) -> str:
    canonical = json.dumps(
        entries,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _stage_build_source(
    destination: Path, source_date_epoch: int
) -> tuple[str, tuple[dict[str, object], ...]]:
    destination.mkdir(mode=0o700)
    copied_paths: list[str] = []
    for relative_name in BUILD_FILES:
        source = PROJECT_ROOT / relative_name
        if not source.is_file():
            raise BuildError(f"required build input is missing: {relative_name}")
        _copy_regular_file(source, destination / relative_name)
        copied_paths.append(relative_name)

    for source in sorted(PACKAGE_ROOT.rglob("*.py")):
        relative = source.relative_to(PROJECT_ROOT).as_posix()
        _copy_regular_file(source, destination / relative)
        copied_paths.append(relative)

    for staged in sorted(destination.rglob("*"), reverse=True):
        os.utime(staged, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    os.utime(destination, (source_date_epoch, source_date_epoch))

    entries = _source_entries(destination, copied_paths)
    return _source_tree_digest(entries), entries


def _sanitized_build_environment(source_date_epoch: int) -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.upper().startswith("PYTHON"):
            environment.pop(key)
    environment.update(
        {
            "LC_ALL": "C",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "TZ": "UTC",
        }
    )
    return environment


def _build_once(source: Path, output: Path, source_date_epoch: int) -> None:
    output.mkdir(mode=0o700)
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-s",
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(output),
            str(source),
        ],
        cwd=source,
        env=_sanitized_build_environment(source_date_epoch),
        capture_output=True,
        check=False,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise BuildError(f"package build failed: {completed.stderr.strip()}")
    wheel_names = tuple(output.glob("*.whl"))
    sdist_names = tuple(output.glob("*.tar.gz"))
    if len(wheel_names) != 1:
        raise BuildError("package build did not emit exactly one wheel")
    if len(sdist_names) != 1:
        raise BuildError("package build did not emit exactly one source distribution")
    _normalize_wheel(wheel_names[0], source_date_epoch)
    _normalize_source_distribution(sdist_names[0], source_date_epoch)


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    windows_absolute = len(name) >= 3 and name[0].isalpha() and name[1] == ":" and name[2] == "/"
    return (
        bool(name)
        and name == path.as_posix()
        and name != "."
        and not name.endswith("/")
        and not path.is_absolute()
        and not windows_absolute
        and all(part not in {"", ".", ".."} for part in path.parts)
        and "\\" not in name
        and not any(ord(character) < 32 or ord(character) == 127 for character in name)
    )


def _normalized_zip_datetime(source_date_epoch: int) -> tuple[int, int, int, int, int, int]:
    try:
        value = datetime.fromtimestamp(source_date_epoch, tz=UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise BuildError("source-date-epoch is not representable as a ZIP timestamp") from exc
    if not 1980 <= value.year <= 2107:
        raise BuildError("source-date-epoch is outside the ZIP timestamp range")
    return (value.year, value.month, value.day, value.hour, value.minute, value.second)


def _normalize_wheel(path: Path, source_date_epoch: int) -> None:
    source_bytes = path.read_bytes()
    members: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(source_bytes), mode="r") as archive:
            for member in archive.infolist():
                if not _safe_archive_name(member.filename) or member.filename in seen:
                    raise BuildError("wheel contains an unsafe or duplicate path")
                seen.add(member.filename)
                encoded_mode = member.external_attr >> 16
                file_type = stat.S_IFMT(encoded_mode)
                if member.is_dir() or file_type not in {0, stat.S_IFREG}:
                    raise BuildError("wheel contains a non-regular member")
                if member.flag_bits & 0x1:
                    raise BuildError("wheel contains an encrypted member")
                members.append((member.filename, archive.read(member)))
    except BuildError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise BuildError("wheel could not be normalized") from exc

    normalized_bytes = io.BytesIO()
    zip_datetime = _normalized_zip_datetime(source_date_epoch)
    with zipfile.ZipFile(
        normalized_bytes,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name, content in sorted(members):
            information = zipfile.ZipInfo(name, date_time=zip_datetime)
            information.compress_type = zipfile.ZIP_DEFLATED
            information.create_system = 3
            information.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(
                information,
                content,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
    path.write_bytes(normalized_bytes.getvalue())
    path.chmod(0o644)


def _normalize_source_distribution(path: Path, source_date_epoch: int) -> None:
    source_bytes = path.read_bytes()
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(source_bytes), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not _safe_archive_name(member.name) or member.name in seen:
                    raise BuildError("source distribution contains an unsafe or duplicate path")
                seen.add(member.name)
                if member.isdir():
                    members.append((member, None))
                    continue
                if not member.isfile():
                    raise BuildError("source distribution contains a non-regular member")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BuildError("source distribution member could not be read")
                members.append((member, extracted.read()))
    except (tarfile.TarError, OSError) as exc:
        raise BuildError("source distribution could not be normalized") from exc

    compressed_bytes = io.BytesIO()
    with (
        gzip.GzipFile(
            fileobj=compressed_bytes,
            filename="",
            mode="wb",
            compresslevel=9,
            mtime=source_date_epoch,
        ) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for original, content in sorted(members, key=lambda item: item[0].name):
            normalized = tarfile.TarInfo(original.name)
            normalized.gid = 0
            normalized.gname = ""
            normalized.mode = 0o755 if original.isdir() else 0o644
            normalized.mtime = source_date_epoch
            normalized.type = tarfile.DIRTYPE if original.isdir() else tarfile.REGTYPE
            normalized.uid = 0
            normalized.uname = ""
            if content is None:
                archive.addfile(normalized)
            else:
                normalized.size = len(content)
                archive.addfile(normalized, io.BytesIO(content))
    path.write_bytes(compressed_bytes.getvalue())
    path.chmod(0o644)


def _expected_artifact_names(version: str) -> tuple[str, str]:
    return (
        f"{NORMALIZED_DISTRIBUTION}-{version}.tar.gz",
        f"{NORMALIZED_DISTRIBUTION}-{version}-py3-none-any.whl",
    )


def _compare_builds(first: Path, second: Path, expected_names: tuple[str, str]) -> None:
    first_names = {path.name for path in first.iterdir() if path.is_file()}
    second_names = {path.name for path in second.iterdir() if path.is_file()}
    expected = set(expected_names)
    if first_names != expected or second_names != expected:
        raise BuildError("package build emitted an unexpected artifact set")
    for name in expected_names:
        if (first / name).read_bytes() != (second / name).read_bytes():
            raise BuildError(f"repeated package builds differ: {name}")


def _build_environment(source: Path, source_date_epoch: int) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-B", "-s", "-c", _BUILD_ENVIRONMENT_PROGRAM],
        cwd=source,
        env=_sanitized_build_environment(source_date_epoch),
        capture_output=True,
        check=False,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 8192:
        raise BuildError("build environment could not be identified")
    try:
        environment = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BuildError("build environment could not be identified") from exc
    expected_keys = {
        "implementation",
        "machine",
        "operating_system",
        "operating_system_release",
        "python",
        "tools",
    }
    if not isinstance(environment, dict) or set(environment) != expected_keys:
        raise BuildError("build environment metadata is incomplete")
    if environment.get("tools") != EXPECTED_BUILD_TOOLS:
        raise BuildError("build tool versions do not match the release-candidate pins")
    if any(
        not isinstance(environment.get(key), str)
        or not environment[key]
        or len(environment[key]) > 128
        or "\n" in environment[key]
        or "\r" in environment[key]
        for key in expected_keys - {"tools"}
    ):
        raise BuildError("build environment metadata is invalid")
    return environment


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _path_matches_descriptor(path: Path, descriptor: int) -> bool:
    try:
        expected = os.fstat(descriptor)
        actual = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISDIR(expected.st_mode)
        and stat.S_ISDIR(actual.st_mode)
        and (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)
    )


def _entry_matches_directory(name: str, parent_descriptor: int, identity: tuple[int, int]) -> bool:
    try:
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == identity


def _open_empty_output_directory(path: Path) -> tuple[int, int, bool]:
    _preflight_output(path)
    parent_descriptor = -1
    output_descriptor = -1
    created = False
    created_identity: tuple[int, int] | None = None
    try:
        parent_descriptor = os.open(path.parent, _directory_open_flags())
        if not _path_matches_descriptor(path.parent, parent_descriptor):
            raise BuildError("output parent directory changed during publication")
        try:
            metadata = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.mkdir(path.name, mode=0o700, dir_fd=parent_descriptor)
            except FileExistsError as exc:
                raise BuildError("output directory must be new or empty") from exc
            created = True
        else:
            if stat.S_ISLNK(metadata.st_mode):
                raise BuildError("output directory must not be a symbolic link")
            if not stat.S_ISDIR(metadata.st_mode):
                raise BuildError("output directory must be new or empty")

        output_descriptor = os.open(
            path.name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
        if created:
            os.fchmod(output_descriptor, 0o700)
        output_metadata = os.fstat(output_descriptor)
        if not stat.S_ISDIR(output_metadata.st_mode):
            raise BuildError("output directory must be new or empty")
        output_identity = (output_metadata.st_dev, output_metadata.st_ino)
        if created:
            created_identity = output_identity
        if os.listdir(output_descriptor):
            raise BuildError("output directory must be new or empty")
        if not _entry_matches_directory(path.name, parent_descriptor, output_identity):
            raise BuildError("output directory changed during publication")
        return parent_descriptor, output_descriptor, created
    except BaseException:
        if output_descriptor >= 0:
            os.close(output_descriptor)
        if (
            created
            and created_identity is not None
            and parent_descriptor >= 0
            and _entry_matches_directory(path.name, parent_descriptor, created_identity)
        ):
            with contextlib.suppress(OSError):
                os.rmdir(path.name, dir_fd=parent_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        raise


def _write_exclusive_at(directory_descriptor: int, name: str, content: bytes) -> tuple[int, int]:
    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise BuildError("release bundle contains an invalid output name")
    descriptor = -1
    identity: tuple[int, int] | None = None
    flags = os.O_WRONLY | os.O_CLOEXEC | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o644, dir_fd=directory_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BuildError("release bundle output is not a regular file")
        identity = (metadata.st_dev, metadata.st_ino)
        os.fchmod(descriptor, 0o644)
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("release bundle write made no progress")
            offset += written
        os.fsync(descriptor)
        return identity
    except BaseException:
        if descriptor >= 0 and identity is not None:
            try:
                current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == identity:
                    os.unlink(name, dir_fd=directory_descriptor)
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _remove_owned_file(directory_descriptor: int, name: str, identity: tuple[int, int]) -> None:
    try:
        current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=directory_descriptor)
    except OSError:
        pass


def _verify_published_bundle(
    output: Path,
    parent_descriptor: int,
    output_descriptor: int,
    bundle: dict[str, bytes],
    identities: dict[str, tuple[int, int]],
) -> None:
    if not _path_matches_descriptor(output.parent, parent_descriptor):
        raise BuildError("output parent directory changed during publication")
    output_metadata = os.fstat(output_descriptor)
    output_identity = (output_metadata.st_dev, output_metadata.st_ino)
    if not _entry_matches_directory(output.name, parent_descriptor, output_identity):
        raise BuildError("output directory changed during publication")
    if set(os.listdir(output_descriptor)) != set(bundle):
        raise BuildError("release bundle file set changed during publication")
    for name, content in bundle.items():
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=output_descriptor,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or metadata.st_size != len(content)
                or (metadata.st_dev, metadata.st_ino) != identities[name]
            ):
                raise BuildError("release bundle output changed during publication")
            observed = bytearray()
            while len(observed) < len(content):
                chunk = os.read(descriptor, min(1024 * 1024, len(content) - len(observed)))
                if not chunk:
                    break
                observed.extend(chunk)
            if bytes(observed) != content or os.read(descriptor, 1):
                raise BuildError("release bundle output changed during publication")
        except OSError as exc:
            raise BuildError("release bundle output changed during publication") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def _publish_release_bundle(output: Path, bundle: dict[str, bytes]) -> None:
    if not bundle:
        raise BuildError("release bundle must not be empty")
    if any(
        name in {"", ".", ".."} or "/" in name or "\\" in name or not isinstance(content, bytes)
        for name, content in bundle.items()
    ):
        raise BuildError("release bundle contains an invalid output")
    parent_descriptor, output_descriptor, created = _open_empty_output_directory(output)
    output_metadata = os.fstat(output_descriptor)
    output_identity = (output_metadata.st_dev, output_metadata.st_ino)
    identities: dict[str, tuple[int, int]] = {}
    try:
        for name, content in sorted(bundle.items()):
            identities[name] = _write_exclusive_at(output_descriptor, name, content)
        os.fsync(output_descriptor)
        _verify_published_bundle(
            output,
            parent_descriptor,
            output_descriptor,
            bundle,
            identities,
        )
    except BuildError:
        for name, identity in identities.items():
            _remove_owned_file(output_descriptor, name, identity)
        raise
    except OSError as exc:
        for name, identity in identities.items():
            _remove_owned_file(output_descriptor, name, identity)
        raise BuildError("release bundle could not be published") from exc
    except BaseException:
        for name, identity in identities.items():
            _remove_owned_file(output_descriptor, name, identity)
        raise
    finally:
        os.close(output_descriptor)
        if created and _entry_matches_directory(output.name, parent_descriptor, output_identity):
            with contextlib.suppress(OSError):
                os.rmdir(output.name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def build_release(output: Path, *, source_date_epoch: int) -> None:
    if source_date_epoch < 315532800:
        raise BuildError("source-date-epoch must be a positive timestamp from 1980 or later")
    _preflight_output(output)
    version = _package_version()
    expected_names = _expected_artifact_names(version)

    with tempfile.TemporaryDirectory(prefix="erpsec-release-build-") as temporary_name:
        temporary = Path(temporary_name)
        source_a = temporary / "source-a"
        source_b = temporary / "source-b"
        output_a = temporary / "output-a"
        output_b = temporary / "output-b"
        tree_sha256_a, source_files_a = _stage_build_source(source_a, source_date_epoch)
        tree_sha256_b, source_files_b = _stage_build_source(source_b, source_date_epoch)
        if tree_sha256_a != tree_sha256_b or source_files_a != source_files_b:
            raise BuildError("staged build sources differ")
        build_environment = _build_environment(source_a, source_date_epoch)
        _build_once(source_a, output_a, source_date_epoch)
        _build_once(source_b, output_b, source_date_epoch)
        _compare_builds(output_a, output_b, expected_names)

        artifacts: list[dict[str, object]] = []
        bundle: dict[str, bytes] = {}
        for name in expected_names:
            source_artifact = output_a / name
            artifact_content = source_artifact.read_bytes()
            bundle[name] = artifact_content
            artifacts.append(
                {
                    "filename": name,
                    "sha256": hashlib.sha256(artifact_content).hexdigest(),
                    "size": len(artifact_content),
                }
            )

    manifest = {
        "artifacts": artifacts,
        "build_environment": build_environment,
        "package": {"distribution": DISTRIBUTION, "version": version},
        "schema_version": "erpsec.build-manifest/v1",
        "source": {
            "files": list(source_files_a),
            "tree_sha256": tree_sha256_a,
            "vcs_revision": None,
            "vcs_state": "unavailable",
        },
        "source_date_epoch": source_date_epoch,
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    bundle["build-manifest.json"] = manifest_bytes
    _publish_release_bundle(output, bundle)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser(
        "build", help="build and compare a release candidate twice"
    )
    build_parser.add_argument("--output", required=True, type=Path)
    build_parser.add_argument(
        "--source-date-epoch",
        default=DEFAULT_SOURCE_DATE_EPOCH,
        type=int,
        help=f"normalized build timestamp (default: {DEFAULT_SOURCE_DATE_EPOCH})",
    )
    return parser


def main(arguments: list[str] | None = None) -> int:
    namespace = _parser().parse_args(arguments)
    try:
        if namespace.command == "build":
            build_release(
                namespace.output,
                source_date_epoch=namespace.source_date_epoch,
            )
    except (BuildError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
