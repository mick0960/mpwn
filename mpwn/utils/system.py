"""
System utilities for MPwn.

Provides functions for architecture detection, dependency parsing,
and other system-level operations.
"""

import re
import subprocess
from pathlib import Path

from mpwn.models import Architecture, LibraryMapping
from mpwn.utils.console import error
from mpwn.config import LD_PATTERNS


def detect_arch(executable_path: str | Path) -> Architecture:
    """Detect the architecture of an executable using the file command.

    Args:
        executable_path: Path to the executable file

    Returns:
        Architecture enum value (AMD64 or I386)

    Raises:
        SystemExit: If architecture detection fails or is unsupported
    """
    try:
        output = subprocess.check_output(
            ["file", str(executable_path)],
            text=True
        )
        return Architecture.from_file_output(output)
    except subprocess.CalledProcessError:
        error("Failed to detect executable architecture")
    except ValueError as e:
        error(str(e))


def parse_ldd_output(executable_path: str | Path) -> list[LibraryMapping]:
    """Parse ldd output to get linked library dependencies.

    Args:
        executable_path: Path to the executable file

    Returns:
        List of LibraryMapping objects representing linked libraries

    Raises:
        SystemExit: If ldd parsing fails
    """
    result: list[LibraryMapping] = []

    try:
        output = subprocess.check_output(
            ["ldd", str(executable_path)],
            text=True
        )

        for line in output.splitlines():
            # Match pattern: libname.so => /path/to/lib (address)
            match = re.match(r"\s*(\S+)\s+=>\s+(\S+)", line)
            if match:
                libname, libpath = match.group(1), match.group(2)

                # Skip LD loader entries
                if _is_ld_loader(libname):
                    continue

                result.append(LibraryMapping(
                    name=libname,
                    path=Path(libpath) if libpath != "not" else None
                ))
            else:
                # Handle format: libname.so (address)
                tokens = line.strip().split()
                if len(tokens) == 2 and tokens[1].startswith("("):
                    libname = tokens[0]
                    if _is_ld_loader(libname):
                        continue
                    result.append(LibraryMapping(name=libname, path=None))

    except subprocess.CalledProcessError:
        error("Can't parse ldd's output!")

    return result


def _is_ld_loader(libname: str) -> bool:
    """Check if a library name is an LD loader.

    Args:
        libname: Library name to check

    Returns:
        True if the library is an LD loader
    """
    return any(pattern in libname for pattern in LD_PATTERNS)


def is_executable(file_path: Path) -> bool:
    """Check if a file is an ELF executable.

    Args:
        file_path: Path to check

    Returns:
        True if file is an ELF executable
    """
    try:
        import magic
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(str(file_path))
        return "executable" in file_type or file_type == "application/x-pie-executable"
    except Exception:
        return False


def is_shared_library(file_path: Path) -> bool:
    """Check if a file is a shared library.

    Args:
        file_path: Path to check

    Returns:
        True if file is a shared library
    """
    try:
        import magic
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(str(file_path))
        return file_type == "application/x-sharedlib"
    except Exception:
        return False
