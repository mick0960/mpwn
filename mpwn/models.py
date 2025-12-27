"""
Data models for MPwn.

Contains dataclass definitions for challenge file information,
library mappings, and architecture types.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from enum import Enum


class Architecture(Enum):
    """Supported architectures for binaries."""
    AMD64 = "amd64"
    I386 = "i386"

    @classmethod
    def from_file_output(cls, output: str) -> "Architecture":
        """Parse architecture from 'file' command output.

        Args:
            output: Output string from the 'file' command

        Returns:
            Architecture enum value

        Raises:
            ValueError: If architecture is not supported
        """
        if "ELF 32-bit" in output:
            return cls.I386
        elif "ELF 64-bit" in output:
            return cls.AMD64
        raise ValueError(f"Unsupported architecture in: {output}")

    def __str__(self) -> str:
        return self.value


@dataclass
class LibraryMapping:
    """Represents a shared library and its resolved path.

    Attributes:
        name: Library name (e.g., 'libc.so.6')
        path: Resolved path to the library file
    """
    name: str
    path: Optional[Path] = None

    def __str__(self) -> str:
        if self.path:
            return f"{self.name} => {self.path}"
        return f"{self.name} => (not found)"

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary format for backwards compatibility."""
        return {self.name: str(self.path) if self.path else ""}


@dataclass
class ChallengeFileInfo:
    """
    Information about a CTF challenge's files.

    This class holds all relevant file paths and metadata for a binary
    exploitation challenge, including the target executable, dynamic
    linker, libc, and other shared libraries.

    Attributes:
        executable: Path to the target binary
        ld_loader: Path to the ld.so dynamic linker
        libc: Path to libc.so.6
        other_libs: Additional shared libraries provided with the challenge
        linked_libs: Libraries the executable is linked against (from ldd)
        architecture: Detected binary architecture
    """
    executable: Optional[Path] = None
    ld_loader: Optional[Path] = None
    libc: Optional[Path] = None
    other_libs: list[LibraryMapping] = field(default_factory=list)
    linked_libs: list[LibraryMapping] = field(default_factory=list)
    architecture: Optional[Architecture] = None

    def __str__(self) -> str:
        lines = [
            f"Executable:   {self.executable or '(not set)'}",
            f"LD Loader:    {self.ld_loader or '(not set)'}",
            f"LIBC:         {self.libc or '(not set)'}",
            f"Architecture: {self.architecture.value if self.architecture else '(unknown)'}",
        ]

        if self.other_libs:
            lines.append("Other Libraries:")
            for lib in self.other_libs:
                lines.append(f"  {lib}")

        if self.linked_libs:
            lines.append("Linked Libraries:")
            for lib in self.linked_libs:
                lines.append(f"  {lib}")

        return "\n".join(lines)

    @property
    def is_ready_to_patch(self) -> bool:
        """Check if we have enough info to perform patching.

        Returns:
            True if both executable and ld_loader are set
        """
        return self.executable is not None and self.ld_loader is not None

    def get_library_map(self) -> dict[str, Path]:
        """Build a mapping of library names to paths for patchelf.

        Returns:
            Dictionary mapping library names to their paths
        """
        lib_map: dict[str, Path] = {}
        if self.libc:
            lib_map["libc.so.6"] = self.libc
        for lib in self.other_libs:
            if lib.path:
                lib_map[lib.name] = lib.path
        return lib_map

    @classmethod
    def from_legacy(
        cls,
        executable: str = "",
        ld_editor: str = "",
        libc: str = "",
        other_libs: Optional[list[dict[str, str]]] = None,
        linked_libs: Optional[list[dict[str, str]]] = None,
    ) -> "ChallengeFileInfo":
        """Create from legacy ChalFileInfo-style arguments.

        This method provides backwards compatibility with the old
        ChalFileInfo class structure.

        Args:
            executable: Path string to executable
            ld_editor: Path string to LD loader
            libc: Path string to libc
            other_libs: List of dicts mapping lib names to paths
            linked_libs: List of dicts from ldd output

        Returns:
            New ChallengeFileInfo instance
        """
        other = []
        if other_libs:
            for lib_dict in other_libs:
                for name, path in lib_dict.items():
                    other.append(LibraryMapping(
                        name=name,
                        path=Path(path) if path else None
                    ))

        linked = []
        if linked_libs:
            for lib_dict in linked_libs:
                for name, path in lib_dict.items():
                    linked.append(LibraryMapping(
                        name=name,
                        path=Path(path) if path and not path.startswith("(") else None
                    ))

        return cls(
            executable=Path(executable) if executable else None,
            ld_loader=Path(ld_editor) if ld_editor else None,
            libc=Path(libc) if libc else None,
            other_libs=other,
            linked_libs=linked,
        )
