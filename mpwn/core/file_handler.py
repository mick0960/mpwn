"""
File handler for MPwn.

Handles discovery and classification of challenge files.
"""

from pathlib import Path
from typing import Optional

import magic

from mpwn.models import ChallengeFileInfo, LibraryMapping, Architecture
from mpwn.utils.console import prompt, success
from mpwn.utils.system import parse_ldd_output, detect_arch
from mpwn.libc.version_manager import find_libc_in_version


class FileHandler:
    """Handles discovery and classification of challenge files.

    This class scans a directory for challenge files, identifies
    executables, shared libraries, libc, and ld files.
    """

    def __init__(
        self,
        exe_path: Optional[str] = None,
        libc_version: Optional[str] = None,
        arch: Optional[str] = None,
    ):
        """Initialize the file handler.

        Args:
            exe_path: Path to the target executable (optional)
            libc_version: Specific libc version to use (optional)
            arch: Target architecture (optional)
        """
        self.exe_path = exe_path
        self.libc_version = libc_version
        self.arch = arch
        self.mime = magic.Magic(mime=True)

    def discover_files(self) -> ChallengeFileInfo:
        """Discover and classify files in the current directory.

        Returns:
            ChallengeFileInfo with discovered file paths
        """
        info = ChallengeFileInfo()

        # Set architecture if we have an executable
        if self.exe_path and self.arch:
            try:
                info.architecture = Architecture(self.arch)
            except ValueError:
                pass

        # Handle executable
        if self.exe_path:
            self._handle_executable(info)

        # If we have a specific libc version, use it
        if self.libc_version and self.arch:
            self._use_versioned_libc(info)
            self._scan_other_libs(info, skip_libc_ld=True)
        else:
            self._scan_all_files(info)

        # Parse dependencies if we have an executable
        if info.executable:
            info.linked_libs = parse_ldd_output(info.executable)

        return info

    def _handle_executable(self, info: ChallengeFileInfo) -> None:
        """Handle the executable file selection.

        Args:
            info: ChallengeFileInfo to update
        """
        exe_path = Path(self.exe_path).absolute()

        if exe_path.exists():
            if prompt(f"It seems that you want {self.exe_path} to be the challenge file?"):
                info.executable = exe_path

    def _use_versioned_libc(self, info: ChallengeFileInfo) -> None:
        """Use a specific libc version from the local cache.

        Args:
            info: ChallengeFileInfo to update
        """
        libc_path, ld_path = find_libc_in_version(self.libc_version, self.arch)

        if libc_path:
            info.libc = libc_path
            success(f"Using libc: {libc_path}")

        if ld_path:
            info.ld_loader = ld_path
            success(f"Using ld: {ld_path}")

    def _scan_other_libs(self, info: ChallengeFileInfo, skip_libc_ld: bool = False) -> None:
        """Scan for other shared libraries in the current directory.

        Args:
            info: ChallengeFileInfo to update
            skip_libc_ld: If True, skip libc and ld files
        """
        for file_path in Path(".").iterdir():
            if file_path.is_dir():
                continue

            abs_path = file_path.absolute()
            file_type = self.mime.from_file(str(abs_path))

            if file_type == "application/x-sharedlib":
                name_lower = file_path.name.lower()

                if skip_libc_ld:
                    if "libc" not in name_lower and "ld" not in name_lower:
                        info.other_libs.append(LibraryMapping(
                            name=file_path.name,
                            path=abs_path
                        ))
                else:
                    info.other_libs.append(LibraryMapping(
                        name=file_path.name,
                        path=abs_path
                    ))

    def _scan_all_files(self, info: ChallengeFileInfo) -> None:
        """Scan all files in the current directory.

        This method is used when no specific libc version is requested.
        It discovers executables, libc, ld, and other shared libraries.

        Args:
            info: ChallengeFileInfo to update
        """
        for file_path in Path(".").iterdir():
            if file_path.is_dir():
                continue

            abs_path = file_path.absolute()
            file_type = self.mime.from_file(str(abs_path))
            name_lower = file_path.name.lower()

            # Check for executable
            if "executable" in file_type or file_type == "application/x-pie-executable":
                if not info.executable:
                    if prompt(f"Choosing {file_path.name} as your executable file?"):
                        info.executable = abs_path
                        # Detect architecture from executable
                        try:
                            info.architecture = detect_arch(abs_path)
                        except SystemExit:
                            pass

            # Check for shared library
            elif file_type == "application/x-sharedlib":
                if "libc" in name_lower and not info.libc:
                    info.libc = abs_path
                elif "ld" in name_lower and not info.ld_loader:
                    info.ld_loader = abs_path
                else:
                    info.other_libs.append(LibraryMapping(
                        name=file_path.name,
                        path=abs_path
                    ))


def handle_files(
    exe: str = "",
    libc_version: Optional[str] = None,
    arch: Optional[str] = None,
) -> ChallengeFileInfo:
    """Discover and handle challenge files.

    This is a convenience function wrapping the FileHandler class.
    Maintains backwards compatibility with the original function signature.

    Args:
        exe: Path to the executable
        libc_version: Specific libc version to use
        arch: Target architecture

    Returns:
        ChallengeFileInfo with discovered files
    """
    handler = FileHandler(exe, libc_version, arch)
    return handler.discover_files()
