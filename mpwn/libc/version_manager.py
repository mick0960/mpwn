"""
Version manager for MPwn.

Handles saving, loading, and searching for glibc versions.
"""

import fnmatch
from pathlib import Path

from mpwn.config import LIBS_DIR, VERSION_LIST_PATH, CONFIG_DIR


class VersionManager:
    """Manages glibc version lists and searching.

    This class handles:
    - Saving and loading version lists
    - Searching for local installed versions
    - Searching for stored (cached) version information
    - Finding libc and ld paths within version directories
    """

    def __init__(self):
        """Initialize the version manager."""
        self.libs_dir = LIBS_DIR
        self.version_list_path = VERSION_LIST_PATH

    def save_version_list(self, versions: list[tuple[str, str]]) -> None:
        """Save the list of glibc versions to the version file.

        Args:
            versions: List of (version, arch) tuples
        """
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        with open(self.version_list_path, "w") as f:
            for ver, arch in versions:
                f.write(f"{ver}_{arch}\n")

        print(f"[+] Saved {len(versions)} versions to {self.version_list_path}")

    def load_version_list(self) -> list[tuple[str, str]]:
        """Load the list of glibc versions from the version file.

        Returns:
            List of (version, arch) tuples
        """
        if not self.version_list_path.exists():
            return []

        versions: list[tuple[str, str]] = []

        with open(self.version_list_path, "r") as f:
            for line in f:
                parts = line.strip().split("_")
                if len(parts) >= 2:
                    version = "_".join(parts[:-1])
                    arch = parts[-1]
                    versions.append((version, arch))

        return versions

    def find_local_versions(self, pattern: str, arch: str) -> list[str]:
        """Find local libc versions matching a pattern and architecture.

        Args:
            pattern: Version pattern to match (supports wildcards)
            arch: Architecture to filter for

        Returns:
            List of matching version strings
        """
        if not self.libs_dir.exists():
            return []

        matches: list[str] = []

        for entry in self.libs_dir.iterdir():
            if not entry.is_dir():
                continue

            name = entry.name
            if "_" not in name:
                continue

            ver_part, a = name.rsplit("_", 1)
            if a == arch and fnmatch.fnmatch(ver_part, f"*{pattern}*"):
                matches.append(ver_part)

        return sorted(matches)

    def find_stored_versions(self, pattern: str, arch: str) -> list[tuple[str, str]]:
        """Find stored versions matching a pattern and architecture.

        Args:
            pattern: Version pattern to search for
            arch: Architecture to filter for

        Returns:
            List of matching (version, arch) tuples
        """
        stored = self.load_version_list()
        return [(ver, a) for ver, a in stored if a == arch and pattern in ver]

    def find_libc_in_version(
        self, version: str, arch: str
    ) -> tuple[Path | None, Path | None]:
        """Find libc and ld paths for a given version and architecture.

        Args:
            version: Version string
            arch: Architecture string

        Returns:
            Tuple of (libc_path, ld_path), either may be None if not found
        """
        base_dir = self.libs_dir / f"{version}_{arch}"

        if not base_dir.exists():
            return None, None

        libc_path: Path | None = None
        ld_path: Path | None = None

        for path in base_dir.rglob("*"):
            if not path.is_file():
                continue

            name = path.name

            if name == "libc.so.6":
                libc_path = path
            elif name.startswith("ld") and (
                name.endswith(".so.2") or name.endswith(".so")
            ):
                ld_path = path

            # Stop early if both found
            if libc_path and ld_path:
                break

        return libc_path, ld_path

    def get_version_dir(self, version: str, arch: str) -> Path:
        """Get the directory path for a version.

        Args:
            version: Version string
            arch: Architecture string

        Returns:
            Path to the version directory
        """
        return self.libs_dir / f"{version}_{arch}"

    def version_exists(self, version: str, arch: str) -> bool:
        """Check if a version is installed locally.

        Args:
            version: Version string
            arch: Architecture string

        Returns:
            True if the version directory exists
        """
        return self.get_version_dir(version, arch).exists()


# Module-level convenience functions for backwards compatibility

_manager = VersionManager()


def save_version_list(versions: list[tuple[str, str]]) -> None:
    """Save the list of glibc versions."""
    _manager.save_version_list(versions)


def load_version_list() -> list[tuple[str, str]]:
    """Load the list of glibc versions."""
    return _manager.load_version_list()


def find_local_versions(pattern: str, arch: str) -> list[str]:
    """Find local libc versions matching a pattern."""
    return _manager.find_local_versions(pattern, arch)


def find_stored_versions(pattern: str, arch: str) -> list[tuple[str, str]]:
    """Find stored versions matching a pattern."""
    return _manager.find_stored_versions(pattern, arch)


def find_libc_in_version(
    version: str, arch: str
) -> tuple[Path | None, Path | None]:
    """Find libc and ld paths for a version."""
    return _manager.find_libc_in_version(version, arch)
