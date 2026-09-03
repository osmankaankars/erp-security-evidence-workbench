#!/usr/bin/env python3
"""Inspect release-candidate archives and write deterministic release metadata."""

from __future__ import annotations

import argparse
import email.policy
import gzip
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "erp-security-evidence-workbench"
PROJECT_VERSION = "0.2.0rc1"
EXPECTED_WHEEL_NAME = "erp_security_evidence_workbench-0.2.0rc1-py3-none-any.whl"
EXPECTED_DIST_INFO = "erp_security_evidence_workbench-0.2.0rc1.dist-info"
EXPECTED_LICENSE_EXPRESSION = "MIT"
EXPECTED_LICENSE_FILE = "LICENSE"
PROJECT_LICENSE = PROJECT_ROOT / EXPECTED_LICENSE_FILE
DEFAULT_WHEEL_POLICY = PROJECT_ROOT / "release" / "wheel-members.txt"
DEFAULT_SDIST_POLICY = PROJECT_ROOT / "release" / "sdist-members.txt"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TAR_METADATA_BYTES = 4 * 1024 * 1024
MAX_ZIP_METADATA_BYTES = 4 * 1024 * 1024
MAX_MEMBERS = 512
READ_CHUNK_BYTES = 1024 * 1024
MINIMUM_ZIP_EPOCH = 315532800
GIT_TIMEOUT_SECONDS = 10
MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024

CACHE_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
    }
)
PRIVATE_FILENAMES = frozenset(
    {"agents.md", "claims_policy.md", "private_go_no_go.md", "provenance.md"}
)
WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")
REQUIREMENT_NAME = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?=$|[\s\[<>=!~@;(])"
)
EXTRA_ONLY_MARKER = re.compile(
    r"""^extra\s*==\s*(?:"[A-Za-z0-9][A-Za-z0-9._-]*"|'[A-Za-z0-9][A-Za-z0-9._-]*')$""",
    flags=re.IGNORECASE,
)
LOCAL_PATH_PATTERNS = (
    re.compile(rb"(?:file://)?/Users/[A-Za-z0-9._-]+/"),
    re.compile(rb"(?:file://)?/home/[A-Za-z0-9._-]+/"),
    re.compile(rb"/private/var/folders/"),
    re.compile(rb"[A-Za-z]:\\+Users\\+[^\\\x00\r\n]+\\+"),
)
SECRET_CANARY_PATTERNS = (
    re.compile(rb"ghp_SYNTHETIC_CREDENTIAL_CANARY_[A-Za-z0-9_]+"),
    re.compile(rb"secret-token-ALPHA[0-9]+"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"ghp_[A-Za-z0-9]{20,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----"),
)


class ReleaseArtifactError(RuntimeError):
    """A local release-artifact operation failed closed."""


@dataclass(frozen=True, slots=True)
class _ArchiveMember:
    """One bounded archive member without an extraction destination."""

    name: str
    kind: str
    mode: int | None
    size: int
    data: bytes


@dataclass(slots=True)
class _CappedReader:
    """Bound aggregate reads from a decompressed archive stream."""

    handle: BinaryIO
    limit: int
    consumed: int = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.consumed
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        chunk = self.handle.read(requested)
        self.consumed += len(chunk)
        if self.consumed > self.limit:
            raise ReleaseArtifactError("archive decompressed-size limit exceeded")
        return chunk


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(READ_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _require_regular_file(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReleaseArtifactError(f"{label} is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseArtifactError(f"{label} must be a regular file, not a symbolic link")


def _require_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReleaseArtifactError(f"{label} is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseArtifactError(f"{label} must be a directory, not a symbolic link")


def _canonical_archive_path(name: str, *, member_number: int) -> str:
    if not name or len(name) > 4096 or "\x00" in name:
        raise ReleaseArtifactError(f"archive member {member_number} has an invalid path red flag")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise ReleaseArtifactError(f"archive member {member_number} has an invalid path red flag")

    slash_name = name.replace("\\", "/")
    if slash_name.startswith("/") or WINDOWS_ABSOLUTE.match(slash_name):
        raise ReleaseArtifactError(f"archive member {member_number} has an absolute path red flag")
    parts = slash_name.rstrip("/").split("/")
    if ".." in parts:
        raise ReleaseArtifactError(f"archive member {member_number} has a path traversal red flag")
    if "\\" in name or any(part in {"", "."} for part in parts):
        raise ReleaseArtifactError(
            f"archive member {member_number} has a non-canonical path red flag"
        )
    canonical = PurePosixPath(*parts).as_posix()
    if canonical in {"", "."}:
        raise ReleaseArtifactError(f"archive member {member_number} has an invalid path red flag")
    return canonical


def _policy_member_path(name: str, *, line_number: int) -> str:
    try:
        canonical = _canonical_archive_path(name, member_number=line_number)
    except ReleaseArtifactError as exc:
        raise ReleaseArtifactError(f"member policy line {line_number} is not a safe path") from exc
    if name.endswith("/"):
        raise ReleaseArtifactError(f"member policy line {line_number} must name a regular file")
    return canonical


def _load_policy(path: Path) -> frozenset[str]:
    _require_regular_file(path, label="member policy")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeError as exc:
        raise ReleaseArtifactError("member policy is not valid UTF-8") from exc

    names: set[str] = set()
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped != raw_line:
            raise ReleaseArtifactError(
                f"member policy line {line_number} has surrounding whitespace"
            )
        canonical = _policy_member_path(stripped, line_number=line_number)
        if canonical in names:
            raise ReleaseArtifactError(f"member policy line {line_number} is duplicated")
        names.add(canonical)
    if not names:
        raise ReleaseArtifactError("member policy is empty")
    return frozenset(names)


def _member_kind_from_zip(information: zipfile.ZipInfo) -> tuple[str, int | None]:
    encoded_mode = information.external_attr >> 16
    file_type = stat.S_IFMT(encoded_mode)
    mode = stat.S_IMODE(encoded_mode) if encoded_mode else None
    if file_type == stat.S_IFLNK:
        return "symlink", mode
    if file_type not in {0, stat.S_IFDIR, stat.S_IFREG}:
        return "special", mode
    if information.is_dir():
        if file_type in {0, stat.S_IFDIR} and information.file_size == 0:
            return "directory", mode
        return "special", mode
    if file_type == stat.S_IFDIR:
        return "special", mode
    return "file", mode


def _open_archive_input(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseArtifactError("archive must be a regular file")
        if metadata.st_size > MAX_ARCHIVE_BYTES:
            raise ReleaseArtifactError("archive file-size limit exceeded")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        raise


def _read_bounded_member(
    handle: BinaryIO,
    *,
    declared_size: int,
    member_number: int,
) -> bytes:
    if declared_size < 0 or declared_size > MAX_MEMBER_BYTES:
        raise ReleaseArtifactError(f"archive member {member_number} exceeds the size limit")
    content = bytearray()
    remaining = declared_size
    while remaining:
        requested = min(READ_CHUNK_BYTES, remaining)
        chunk = handle.read(requested)
        if not chunk or len(chunk) > requested:
            raise ReleaseArtifactError(
                f"archive member {member_number} has inconsistent size metadata"
            )
        content.extend(chunk)
        remaining -= len(chunk)
    if handle.read(1):
        raise ReleaseArtifactError(f"archive member {member_number} has inconsistent size metadata")
    return bytes(content)


def _preflight_zip_central_directory(source: BinaryIO) -> int:
    """Bound classic-ZIP central-directory work before ZipFile allocates entries."""

    try:
        archive_size = os.fstat(source.fileno()).st_size
        if archive_size < 22:
            raise ReleaseArtifactError("wheel has invalid central-directory metadata")
        source.seek(-22, os.SEEK_END)
        record = source.read(22)
        if len(record) != 22:
            raise ReleaseArtifactError("wheel has invalid central-directory metadata")
        (
            signature,
            disk_number,
            directory_disk,
            entries_on_disk,
            total_entries,
            directory_size,
            directory_offset,
            comment_size,
        ) = struct.unpack("<4s4H2IH", record)
    except (OSError, struct.error) as exc:
        raise ReleaseArtifactError("wheel has invalid central-directory metadata") from exc

    if signature != b"PK\x05\x06" or comment_size != 0:
        raise ReleaseArtifactError("wheel has unsupported central-directory metadata")
    if disk_number != 0 or directory_disk != 0 or entries_on_disk != total_entries:
        raise ReleaseArtifactError("wheel has unsupported multi-disk metadata")
    if total_entries == 0xFFFF or directory_size == 0xFFFFFFFF or directory_offset == 0xFFFFFFFF:
        raise ReleaseArtifactError("wheel has unsupported ZIP64 metadata")
    if total_entries > MAX_MEMBERS:
        raise ReleaseArtifactError("archive member-count limit exceeded")
    if directory_size > MAX_ZIP_METADATA_BYTES:
        raise ReleaseArtifactError("wheel central-directory size limit exceeded")
    if directory_offset + directory_size != archive_size - 22:
        raise ReleaseArtifactError("wheel has inconsistent central-directory metadata")
    source.seek(0)
    return total_entries


def _read_wheel(path: Path) -> tuple[_ArchiveMember, ...]:
    try:
        with _open_archive_input(path) as source:
            expected_member_count = _preflight_zip_central_directory(source)
            archive = zipfile.ZipFile(source, "r")
            with archive:
                information_list = archive.infolist()
                if len(information_list) != expected_member_count:
                    raise ReleaseArtifactError("wheel central-directory member count changed")
                members: list[_ArchiveMember] = []
                total_size = 0
                for member_number, information in enumerate(information_list, start=1):
                    if information.flag_bits & 0x1:
                        raise ReleaseArtifactError(
                            f"archive member {member_number} has an encryption red flag"
                        )
                    kind, mode = _member_kind_from_zip(information)
                    if information.file_size > MAX_MEMBER_BYTES:
                        raise ReleaseArtifactError(
                            f"archive member {member_number} exceeds the size limit"
                        )
                    total_size += information.file_size
                    if total_size > MAX_TOTAL_MEMBER_BYTES:
                        raise ReleaseArtifactError("archive expanded-size limit exceeded")
                    data = b""
                    if kind == "file":
                        with archive.open(information, "r") as extracted:
                            data = _read_bounded_member(
                                extracted,
                                declared_size=information.file_size,
                                member_number=member_number,
                            )
                    members.append(
                        _ArchiveMember(
                            name=information.filename,
                            kind=kind,
                            mode=mode,
                            size=information.file_size,
                            data=data,
                        )
                    )
    except (zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, ReleaseArtifactError):
            raise
        raise ReleaseArtifactError("wheel is not a readable ZIP archive") from exc
    return tuple(members)


def _read_sdist(path: Path) -> tuple[_ArchiveMember, ...]:
    try:
        with (
            _open_archive_input(path) as source,
            gzip.GzipFile(fileobj=source, mode="rb") as decompressed,
        ):
            bounded_decompressed = _CappedReader(
                decompressed,
                limit=MAX_TOTAL_MEMBER_BYTES + MAX_TAR_METADATA_BYTES,
            )
            with tarfile.open(fileobj=bounded_decompressed, mode="r|") as archive:
                members: list[_ArchiveMember] = []
                total_size = 0
                for member_number, member in enumerate(archive, start=1):
                    if member_number > MAX_MEMBERS:
                        raise ReleaseArtifactError("archive member-count limit exceeded")
                    if member.issym():
                        kind = "symlink"
                    elif member.islnk():
                        kind = "hardlink"
                    elif member.isdir():
                        kind = "directory"
                    elif member.isfile() and not member.issparse():
                        kind = "file"
                    else:
                        kind = "special"
                    if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                        raise ReleaseArtifactError(
                            f"archive member {member_number} exceeds the size limit"
                        )
                    total_size += member.size
                    if total_size > MAX_TOTAL_MEMBER_BYTES:
                        raise ReleaseArtifactError("archive expanded-size limit exceeded")
                    data = b""
                    if kind == "file":
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            raise ReleaseArtifactError(
                                f"archive member {member_number} cannot be read safely"
                            )
                        with extracted:
                            data = _read_bounded_member(
                                extracted,
                                declared_size=member.size,
                                member_number=member_number,
                            )
                    members.append(
                        _ArchiveMember(
                            name=member.name,
                            kind=kind,
                            mode=stat.S_IMODE(member.mode),
                            size=member.size,
                            data=data,
                        )
                    )
    except (gzip.BadGzipFile, tarfile.TarError, EOFError) as exc:
        raise ReleaseArtifactError("source distribution is not a readable tar archive") from exc
    return tuple(members)


def _allowed_directories(policy: frozenset[str]) -> frozenset[str]:
    directories: set[str] = set()
    for member in policy:
        parent = PurePosixPath(member).parent
        while parent.as_posix() != ".":
            directories.add(parent.as_posix())
            parent = parent.parent
    return frozenset(directories)


def _scan_member_path(path: str, *, member_number: int) -> None:
    parts = tuple(part.lower() for part in PurePosixPath(path).parts)
    if any(part in CACHE_PARTS or part.endswith((".pyc", ".pyo")) for part in parts):
        raise ReleaseArtifactError(f"archive member {member_number} has a cache red flag")
    if (
        any(part in PRIVATE_FILENAMES for part in parts)
        or ".codex" in parts
        or any(parts[index : index + 2] == ("docs", "keystone") for index in range(len(parts)))
    ):
        raise ReleaseArtifactError(
            f"archive member {member_number} has a private document red flag"
        )


def _scan_member_content(data: bytes, *, member_number: int) -> None:
    if any(pattern.search(data) for pattern in LOCAL_PATH_PATTERNS):
        raise ReleaseArtifactError(f"archive member {member_number} contains a local path red flag")
    if any(pattern.search(data) for pattern in SECRET_CANARY_PATTERNS):
        raise ReleaseArtifactError(
            f"archive member {member_number} contains a secret-canary red flag"
        )


def _check_mode(member: _ArchiveMember, *, member_number: int) -> None:
    if member.mode is None:
        return
    unsafe_special_bits = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
    if member.mode & (0o022 | unsafe_special_bits):
        raise ReleaseArtifactError(f"archive member {member_number} has an unsafe mode red flag")
    if member.kind == "file" and member.mode & 0o111:
        raise ReleaseArtifactError(f"archive member {member_number} has an unsafe mode red flag")


def inspect_archive(archive_path: Path, *, kind: str, policy_path: Path) -> dict[str, object]:
    """Inspect an archive without extracting it and return a deterministic acceptance record."""

    _require_regular_file(archive_path, label="archive")
    archive_size = archive_path.stat().st_size
    if archive_size > MAX_ARCHIVE_BYTES:
        raise ReleaseArtifactError("archive file-size limit exceeded")
    if kind == "wheel":
        if archive_path.suffix != ".whl":
            raise ReleaseArtifactError("wheel archive must use the .whl suffix")
        members = _read_wheel(archive_path)
    elif kind == "sdist":
        if not (archive_path.name.endswith(".tar.gz") or archive_path.name.endswith(".tgz")):
            raise ReleaseArtifactError("source distribution must use the .tar.gz or .tgz suffix")
        members = _read_sdist(archive_path)
    else:
        raise ReleaseArtifactError("archive kind must be wheel or sdist")

    policy = _load_policy(policy_path)
    allowed_directories = _allowed_directories(policy)
    observed_files: set[str] = set()
    observed_paths: set[str] = set()
    for member_number, member in enumerate(members, start=1):
        canonical = _canonical_archive_path(member.name, member_number=member_number)
        if canonical in observed_paths:
            raise ReleaseArtifactError(
                f"archive member {member_number} has a duplicate member red flag"
            )
        observed_paths.add(canonical)
        _scan_member_path(canonical, member_number=member_number)
        _scan_member_content(canonical.encode("utf-8"), member_number=member_number)
        if member.kind in {"symlink", "hardlink"}:
            raise ReleaseArtifactError(f"archive member {member_number} has a link red flag")
        if member.kind == "special":
            raise ReleaseArtifactError(
                f"archive member {member_number} has a special-file red flag"
            )
        _check_mode(member, member_number=member_number)
        if member.kind == "directory":
            if canonical not in allowed_directories:
                raise ReleaseArtifactError(
                    f"archive member {member_number} has an unexpected member red flag"
                )
            continue
        _scan_member_content(member.data, member_number=member_number)
        observed_files.add(canonical)

    unexpected = observed_files - policy
    if unexpected:
        raise ReleaseArtifactError("archive has an unexpected member red flag")
    missing = policy - observed_files
    if missing:
        raise ReleaseArtifactError("archive has a missing expected member red flag")
    return {
        "archive": archive_path.name,
        "archive_kind": kind,
        "member_count": len(observed_files),
        "red_flags": [],
        "sha256": _sha256(archive_path),
        "status": "accepted",
    }


def _source_date(source_date_epoch: int) -> str:
    if source_date_epoch < MINIMUM_ZIP_EPOCH:
        raise ReleaseArtifactError("source-date-epoch must be a timestamp from 1980 or later")
    try:
        created = datetime.fromtimestamp(source_date_epoch, UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ReleaseArtifactError("source-date-epoch is outside the supported range") from exc
    return created.strftime("%Y-%m-%dT%H:%M:%SZ")


def _requirement_spdx_id(requirement: str) -> str:
    digest = hashlib.sha256(requirement.encode("utf-8")).hexdigest()
    return f"SPDXRef-Requirement-{digest}"


def _requirement_name(requirement: str) -> str:
    match = REQUIREMENT_NAME.match(requirement)
    if match is None:
        raise ReleaseArtifactError("SPDX input wheel has an unsupported Requires-Dist entry")
    return match.group("name")


def _requirement_relationship(requirement: str) -> str:
    _, separator, marker = requirement.partition(";")
    if not separator:
        return "DEPENDS_ON"
    if EXTRA_ONLY_MARKER.fullmatch(marker.strip()) is None:
        raise ReleaseArtifactError("SPDX input wheel has an unsupported Requires-Dist marker")
    return "OPTIONAL_DEPENDENCY_OF"


def _spdx_document(
    wheel_path: Path,
    *,
    source_date_epoch: int,
    requirements: tuple[str, ...],
) -> dict[str, object]:
    wheel_sha256 = _sha256(wheel_path)
    if requirements:
        package_comment = (
            "Wheel METADATA Requires-Dist declarations are represented below as unresolved "
            "requirement packages. This is not an installed-environment inventory and is not "
            "legal, license-compliance, or "
            "vulnerability-clearance evidence."
        )
    else:
        package_comment = (
            "Wheel metadata was verified to declare no Requires-Dist entries. This is not "
            "legal, license-compliance, or "
            "vulnerability-clearance evidence."
        )
    package = {
        "SPDXID": "SPDXRef-Package",
        "checksums": [{"algorithm": "SHA256", "checksumValue": wheel_sha256}],
        "comment": package_comment,
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": EXPECTED_LICENSE_EXPRESSION,
        "name": PROJECT_NAME,
        "packageFileName": wheel_path.name,
        "primaryPackagePurpose": "APPLICATION",
        "supplier": "NOASSERTION",
        "versionInfo": PROJECT_VERSION,
    }
    requirement_packages = [
        {
            "SPDXID": _requirement_spdx_id(requirement),
            "comment": f"Exact unresolved wheel METADATA Requires-Dist declaration: {requirement}",
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": _requirement_name(requirement),
            "primaryPackagePurpose": "LIBRARY",
            "supplier": "NOASSERTION",
        }
        for requirement in requirements
    ]
    dependency_relationships = []
    for requirement in requirements:
        requirement_id = _requirement_spdx_id(requirement)
        relationship = _requirement_relationship(requirement)
        if relationship == "OPTIONAL_DEPENDENCY_OF":
            dependency_relationships.append(
                {
                    "relatedSpdxElement": "SPDXRef-Package",
                    "relationshipType": "OPTIONAL_DEPENDENCY_OF",
                    "spdxElementId": requirement_id,
                }
            )
        else:
            dependency_relationships.append(
                {
                    "relatedSpdxElement": requirement_id,
                    "relationshipType": "DEPENDS_ON",
                    "spdxElementId": "SPDXRef-Package",
                }
            )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _source_date(source_date_epoch),
            "creators": [f"Tool: {PROJECT_NAME}-release-artifacts-{PROJECT_VERSION}"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            f"urn:erpsec:spdx:{PROJECT_NAME}:{PROJECT_VERSION}:sha256:{wheel_sha256}"
        ),
        "name": f"{PROJECT_NAME}-{PROJECT_VERSION}-wheel",
        "packages": [package, *requirement_packages],
        "relationships": [
            {
                "relatedSpdxElement": "SPDXRef-Package",
                "relationshipType": "DESCRIBES",
                "spdxElementId": "SPDXRef-DOCUMENT",
            },
            *dependency_relationships,
        ],
        "spdxVersion": "SPDX-2.3",
    }


def _validate_project_wheel_identity(wheel_path: Path) -> tuple[str, ...]:
    if wheel_path.name != EXPECTED_WHEEL_NAME:
        raise ReleaseArtifactError("SPDX input is not the expected 0.2.0rc1 wheel filename")
    metadata_name = f"{EXPECTED_DIST_INFO}/METADATA"
    license_name = f"{EXPECTED_DIST_INFO}/licenses/{EXPECTED_LICENSE_FILE}"
    try:
        with _open_archive_input(wheel_path) as source, zipfile.ZipFile(source, "r") as archive:
            information = archive.getinfo(metadata_name)
            if information.file_size > MAX_MEMBER_BYTES:
                raise ReleaseArtifactError("SPDX input wheel metadata exceeds the size limit")
            with archive.open(information, "r") as extracted:
                metadata_bytes = _read_bounded_member(
                    extracted,
                    declared_size=information.file_size,
                    member_number=1,
                )
            license_information = archive.getinfo(license_name)
            if license_information.file_size > MAX_MEMBER_BYTES:
                raise ReleaseArtifactError("SPDX input wheel license exceeds the size limit")
            with archive.open(license_information, "r") as extracted:
                license_bytes = _read_bounded_member(
                    extracted,
                    declared_size=license_information.file_size,
                    member_number=2,
                )
    except (KeyError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ReleaseArtifactError("SPDX input wheel has no readable project metadata") from exc
    try:
        metadata = BytesParser(policy=email.policy.default).parsebytes(metadata_bytes)
    except (TypeError, ValueError) as exc:
        raise ReleaseArtifactError("SPDX input wheel has invalid project metadata") from exc
    if metadata.get("Name") != PROJECT_NAME or metadata.get("Version") != PROJECT_VERSION:
        raise ReleaseArtifactError("SPDX input wheel identity does not match the project release")
    license_files = tuple(str(value) for value in metadata.get_all("License-File", []))
    if metadata.get("License-Expression") != EXPECTED_LICENSE_EXPRESSION or license_files != (
        EXPECTED_LICENSE_FILE,
    ):
        raise ReleaseArtifactError("SPDX input wheel license metadata is inconsistent")
    if license_bytes != PROJECT_LICENSE.read_bytes():
        raise ReleaseArtifactError("SPDX input wheel license content is inconsistent")
    raw_requirements = metadata.get_all("Requires-Dist", [])
    if len(raw_requirements) > MAX_MEMBERS:
        raise ReleaseArtifactError("SPDX input wheel has too many Requires-Dist entries")
    requirements: set[str] = set()
    for raw_requirement in raw_requirements:
        requirement = str(raw_requirement)
        if (
            not requirement
            or len(requirement.encode("utf-8")) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in requirement)
        ):
            raise ReleaseArtifactError("SPDX input wheel has an invalid Requires-Dist entry")
        _requirement_name(requirement)
        _requirement_relationship(requirement)
        if requirement in requirements:
            raise ReleaseArtifactError("SPDX input wheel has a duplicate Requires-Dist entry")
        requirements.add(requirement)
    return tuple(sorted(requirements))


def _atomic_write(path: Path, content: bytes) -> None:
    parent = path.parent
    _require_directory(parent, label="output parent")
    if path.is_symlink():
        raise ReleaseArtifactError("output must not be a symbolic link")
    if path.exists() and not path.is_file():
        raise ReleaseArtifactError("output must be a regular file")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def write_spdx_sbom(
    wheel_path: Path,
    output_path: Path,
    *,
    policy_path: Path,
    source_date_epoch: int,
) -> dict[str, object]:
    """Inspect one wheel and atomically write its deterministic SPDX 2.3 document."""

    inspection = inspect_archive(wheel_path, kind="wheel", policy_path=policy_path)
    requirements = _validate_project_wheel_identity(wheel_path)
    if output_path.absolute() == wheel_path.absolute():
        raise ReleaseArtifactError("SPDX output must be distinct from the wheel")
    document = _spdx_document(
        wheel_path,
        source_date_epoch=source_date_epoch,
        requirements=requirements,
    )
    rendered = json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8")
    _atomic_write(output_path, rendered + b"\n")
    return {
        "artifact_sha256": inspection["sha256"],
        "output": output_path.name,
        "spdx_version": "SPDX-2.3",
        "status": "written",
    }


def _artifact_files(artifact_dir: Path) -> tuple[Path, ...]:
    _require_directory(artifact_dir, label="artifact directory")
    files: list[Path] = []
    for entry in sorted(artifact_dir.iterdir(), key=lambda path: path.name):
        if entry.name == "SHA256SUMS":
            continue
        if entry.is_symlink() or not entry.is_file():
            raise ReleaseArtifactError("artifact directory contains a non-regular entry")
        _canonical_archive_path(entry.name, member_number=len(files) + 1)
        files.append(entry)
    if not files:
        raise ReleaseArtifactError("artifact directory contains no files to checksum")
    return tuple(files)


def write_sha256sums(artifact_dir: Path) -> dict[str, object]:
    """Write a sorted SHA256SUMS for direct artifact files, excluding SHA256SUMS itself."""

    files = _artifact_files(artifact_dir)
    lines = [f"{_sha256(path)}  {path.name}\n" for path in files]
    output = artifact_dir / "SHA256SUMS"
    _atomic_write(output, "".join(lines).encode("utf-8"))
    return {
        "artifact_count": len(files),
        "output": output.name,
        "status": "written",
    }


def _run_git(
    source_root: Path,
    *arguments: str,
    max_stdout_bytes: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "--literal-pathspecs", "-C", str(source_root), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseArtifactError("source snapshot could not inspect committed files") from exc
    if completed.returncode != 0 or len(completed.stdout) > max_stdout_bytes:
        raise ReleaseArtifactError("source snapshot could not inspect committed files")
    return completed.stdout


def _git_revision(source_root: Path) -> str:
    try:
        rendered = _run_git(source_root, "rev-parse", "--verify", "HEAD")
        revision = rendered.decode("ascii").strip()
    except (ReleaseArtifactError, UnicodeError) as exc:
        raise ReleaseArtifactError("source snapshot requires a resolvable committed HEAD") from exc
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is None:
        raise ReleaseArtifactError("source snapshot received an invalid HEAD object ID")
    return revision


def _require_clean_tracked_state(source_root: Path) -> None:
    if _run_git(source_root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise ReleaseArtifactError("source snapshot requires a clean tracked worktree")
    rendered = _run_git(source_root, "ls-files", "-v", "-z")
    records = rendered.split(b"\0")
    if records[-1:] == [b""]:
        records.pop()
    if not records or len(records) > MAX_MEMBERS:
        raise ReleaseArtifactError("source snapshot tracked-file count is outside the limit")
    for record in records:
        if len(record) < 3 or record[1:2] != b" " or record[:1] != b"H":
            raise ReleaseArtifactError("source snapshot rejects non-ordinary tracked index entries")


def _committed_snapshot_entries(
    source_root: Path,
    *,
    revision: str,
) -> tuple[dict[str, object], ...]:
    rendered = _run_git(source_root, "ls-tree", "-r", "-z", "--full-tree", revision)
    records = rendered.split(b"\0")
    if records[-1:] == [b""]:
        records.pop()
    if not records or len(records) > MAX_MEMBERS:
        raise ReleaseArtifactError("source snapshot committed-file count is outside the limit")

    entries: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    aggregate_size = 0
    for member_number, record in enumerate(records, start=1):
        header, separator, raw_name = record.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3:
            raise ReleaseArtifactError("source snapshot received malformed Git tree metadata")
        raw_mode, raw_kind, raw_object_id = fields
        if raw_mode not in {b"100644", b"100755"} or raw_kind != b"blob":
            raise ReleaseArtifactError(
                "source snapshot rejects symlinks, submodules, and special committed entries"
            )
        try:
            relative = raw_name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseArtifactError("source snapshot contains a non-UTF-8 path") from exc
        _canonical_archive_path(relative, member_number=member_number)
        _scan_member_path(relative, member_number=member_number)
        if relative in seen_paths:
            raise ReleaseArtifactError("source snapshot contains a duplicate committed path")
        seen_paths.add(relative)

        try:
            object_id = raw_object_id.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ReleaseArtifactError("source snapshot contains a non-ASCII object ID") from exc
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None:
            raise ReleaseArtifactError("source snapshot contains an invalid Git object ID")
        try:
            size_rendered = _run_git(source_root, "cat-file", "-s", object_id)
            size = int(size_rendered.decode("ascii").strip())
        except (ReleaseArtifactError, UnicodeError, ValueError) as exc:
            raise ReleaseArtifactError(
                "source snapshot could not read a committed blob size"
            ) from exc
        if size < 0 or size > MAX_MEMBER_BYTES:
            raise ReleaseArtifactError("source snapshot committed file exceeds the size limit")
        aggregate_size += size
        if aggregate_size > MAX_TOTAL_MEMBER_BYTES:
            raise ReleaseArtifactError("source snapshot committed files exceed the aggregate limit")
        data = _run_git(
            source_root,
            "cat-file",
            "blob",
            object_id,
            max_stdout_bytes=MAX_MEMBER_BYTES,
        )
        if len(data) != size:
            raise ReleaseArtifactError("source snapshot received inconsistent committed blob data")
        entries.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size": size})
    return tuple(sorted(entries, key=lambda entry: str(entry["path"])))


def write_source_snapshot(source_root: Path, output_path: Path) -> dict[str, object]:
    """Write a deterministic manifest from the exact committed HEAD tree."""

    _require_directory(source_root, label="source root")
    revision = _git_revision(source_root)
    _require_clean_tracked_state(source_root)
    entries = _committed_snapshot_entries(source_root, revision=revision)
    _require_clean_tracked_state(source_root)
    if _git_revision(source_root) != revision:
        raise ReleaseArtifactError("source snapshot HEAD changed during inspection")

    tree_digest = hashlib.sha256()
    for entry in entries:
        tree_digest.update(str(entry["path"]).encode("utf-8"))
        tree_digest.update(b"\0")
        tree_digest.update(str(entry["sha256"]).encode("ascii"))
        tree_digest.update(b"\0")
        tree_digest.update(str(entry["size"]).encode("ascii"))
        tree_digest.update(b"\n")
    manifest = {
        "files": entries,
        "project": {"name": PROJECT_NAME, "version": PROJECT_VERSION},
        "schema_version": "erpsec.release-source-snapshot/v1",
        "tree_sha256": tree_digest.hexdigest(),
        "vcs_revision": revision,
    }
    rendered = json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8")
    _atomic_write(output_path, rendered + b"\n")
    return {
        "file_count": len(entries),
        "output": output_path.name,
        "status": "written",
        "vcs_revision": manifest["vcs_revision"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="inspect one wheel or sdist")
    inspect_parser.add_argument("--archive", required=True, type=Path)
    inspect_parser.add_argument("--kind", required=True, choices=("wheel", "sdist"))
    inspect_parser.add_argument("--policy", type=Path)

    sbom_parser = subparsers.add_parser("sbom", help="write SPDX 2.3 JSON for one wheel")
    sbom_parser.add_argument("--wheel", required=True, type=Path)
    sbom_parser.add_argument("--policy", default=DEFAULT_WHEEL_POLICY, type=Path)
    sbom_parser.add_argument("--output", required=True, type=Path)
    sbom_parser.add_argument("--source-date-epoch", required=True, type=int)

    checksum_parser = subparsers.add_parser(
        "checksums", help="write sorted SHA256SUMS for a flat artifact directory"
    )
    checksum_parser.add_argument("--artifact-dir", required=True, type=Path)

    snapshot_parser = subparsers.add_parser(
        "source-snapshot", help="write a deterministic local source snapshot manifest"
    )
    snapshot_parser.add_argument("--source-root", required=True, type=Path)
    snapshot_parser.add_argument("--output", required=True, type=Path)
    return parser


def _render_result(result: dict[str, object]) -> None:
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(arguments)
    try:
        if namespace.command == "inspect":
            policy = namespace.policy
            if policy is None:
                policy = DEFAULT_WHEEL_POLICY if namespace.kind == "wheel" else DEFAULT_SDIST_POLICY
            result = inspect_archive(
                namespace.archive,
                kind=namespace.kind,
                policy_path=policy,
            )
        elif namespace.command == "sbom":
            result = write_spdx_sbom(
                namespace.wheel,
                namespace.output,
                policy_path=namespace.policy,
                source_date_epoch=namespace.source_date_epoch,
            )
        elif namespace.command == "checksums":
            result = write_sha256sums(namespace.artifact_dir)
        elif namespace.command == "source-snapshot":
            result = write_source_snapshot(namespace.source_root, namespace.output)
        else:  # pragma: no cover - argparse requires a known subcommand.
            raise ReleaseArtifactError("unknown release-artifact operation")
    except ReleaseArtifactError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        print("error: filesystem or archive operation failed", file=sys.stderr)
        return 2
    _render_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
