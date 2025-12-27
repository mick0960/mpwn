"""
Patcher for MPwn.

Handles patching executables with specific libc versions.
"""

import subprocess
from pathlib import Path
from shutil import copy2
from typing import Optional

from mpwn.config import LIBS_DIR, ensure_directories
from mpwn.models import ChallengeFileInfo, Architecture
from mpwn.utils.console import prompt, success, error, info
from mpwn.utils.system import detect_arch
from mpwn.utils.selection import select_version_from_local, select_version_from_stored
from mpwn.libc.downloader import download_glibc_version
from mpwn.libc.version_manager import (
    VersionManager,
    find_local_versions,
    find_stored_versions,
)
from mpwn.core.file_handler import FileHandler
from mpwn.core.script_generator import generate_scripts


class Patcher:
    """Handles patching executables with different libc versions.

    This class orchestrates the full patching workflow:
    1. Detect architecture
    2. Find/download appropriate libc version
    3. Collect challenge files
    4. Apply patches using patchelf
    5. Generate exploit script
    """

    def __init__(
        self,
        executable: str,
        libc_version: Optional[str] = None,
    ):
        """Initialize the patcher.

        Args:
            executable: Path to the target executable
            libc_version: Specific libc version to use (optional)
        """
        self.executable = executable
        self.libc_version = libc_version
        self.architecture: Optional[Architecture] = None
        self.final_version: Optional[str] = None
        self.challenge_info: Optional[ChallengeFileInfo] = None

    def run(self) -> ChallengeFileInfo:
        """Execute the full patching workflow.

        Returns:
            ChallengeFileInfo with all file information

        Raises:
            SystemExit: If executable doesn't exist or patching fails
        """
        # Validate executable exists
        if not Path(f"./{self.executable}").exists():
            error("Unknown executable!")

        # Initialize
        ensure_directories()

        # Detect architecture
        self.architecture = detect_arch(self.executable)

        # Resolve libc version
        if self.libc_version:
            self._resolve_libc_version()

        # Ensure libc is downloaded
        if self.final_version:
            self._ensure_libc_downloaded()
        else:
            info(f"Using dir-provided version for {self.executable}")

        # Collect files
        arch_str = self.architecture.value if self.architecture else "amd64"
        handler = FileHandler(self.executable, self.final_version, arch_str)
        self.challenge_info = handler.discover_files()

        # If no executable was confirmed, error out
        if not self.challenge_info.executable:
            error("No executable file found!")

        # Show info and apply patches
        if self.challenge_info.ld_loader and self.challenge_info.libc:
            print(f"\nCurrent Info:\n{self.challenge_info}\n")

            if prompt("Apply patches?"):
                self._apply_patches()

        # Generate scripts
        generate_scripts(self.challenge_info)

        return self.challenge_info

    def _resolve_libc_version(self) -> None:
        """Resolve the libc version to use.

        Searches local versions first, then stored versions,
        allowing user to select from matches.
        """
        arch = self.architecture.value if self.architecture else "amd64"

        # Try local first
        local_matches = find_local_versions(self.libc_version, arch)

        if local_matches:
            selected = select_version_from_local(local_matches, arch)
            if selected:
                info(f"Selected local version: {selected} for {arch}")
                self.final_version = selected
                return
        else:
            info(f"No local versions found matching '{self.libc_version}' for {arch}")

        # Try stored versions
        stored_matches = find_stored_versions(self.libc_version, arch)

        if stored_matches:
            selected = select_version_from_stored(stored_matches)
            if selected:
                info(f"Selected stored version: {selected} for {arch}")
                self.final_version = selected
        else:
            info(f"No stored versions found matching '{self.libc_version}' for {arch}")

    def _ensure_libc_downloaded(self) -> None:
        """Ensure the selected libc version is downloaded."""
        if not self.final_version:
            return

        arch = self.architecture.value if self.architecture else "amd64"
        version_dir = LIBS_DIR / f"{self.final_version}_{arch}"

        if not version_dir.exists():
            info(f"Downloading glibc {self.final_version} for {arch}...")
            try:
                download_glibc_version(self.final_version, arch)
                success(f"Downloaded glibc {self.final_version} for {arch}")
            except FileNotFoundError as e:
                error(f"Glibc version not found: {e}")
            except Exception as e:
                error(f"Failed to download glibc: {e}")

    def _apply_patches(self) -> None:
        """Apply patches to the executable using patchelf."""
        try:
            # Create backup
            backup_path = Path(str(self.challenge_info.executable) + ".bak")
            copy2(self.challenge_info.executable, backup_path)
            success(f"Backup success: {backup_path}")

            # Build library map
            lib_map = self.challenge_info.get_library_map()

            # Set interpreter
            if self.challenge_info.ld_loader:
                subprocess.run(
                    [
                        "patchelf",
                        "--set-interpreter",
                        str(self.challenge_info.ld_loader),
                        str(self.challenge_info.executable),
                    ],
                    check=True,
                )
                success(f"Set interpreter to: {self.challenge_info.ld_loader}")

            # Replace needed libraries
            for lib in self.challenge_info.linked_libs:
                if lib.name in lib_map:
                    subprocess.run(
                        [
                            "patchelf",
                            "--replace-needed",
                            lib.name,
                            str(lib_map[lib.name]),
                            str(self.challenge_info.executable),
                        ],
                        check=True,
                    )
                    success(f"Replaced {lib.name} --> {lib_map[lib.name]}")

        except subprocess.CalledProcessError as e:
            error(f"Patching failed! {e}")


def patch_program(exe: str = "", libc_version: Optional[str] = None) -> None:
    """Patch an executable with a specific libc version.

    This is a convenience function wrapping the Patcher class.
    Maintains backwards compatibility with the original function.

    Args:
        exe: Path to the executable
        libc_version: Specific libc version to use
    """
    patcher = Patcher(exe, libc_version)
    patcher.run()
