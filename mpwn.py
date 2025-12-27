#!/usr/bin/env python3
"""
MPwn - CTF Pwn Challenge Environment Manager

This file is maintained for backwards compatibility.
The actual implementation is in the mpwn/ package.

Usage:
    mpwn [options] <executable> [libc_version]

For new code, prefer importing from the mpwn package directly:
    from mpwn import ChallengeFileInfo
    from mpwn.core import Patcher
    from mpwn.libc import download_glibc_version
"""

import sys
import os

# Add parent directory to path for package import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Re-export commonly used items for backwards compatibility
from mpwn.config import (
    COMMON_URL,
    OLD_URL,
    LOCAL_BASE,
    DEBS_DIR,
    LIBS_DIR,
)
from mpwn.models import ChallengeFileInfo, LibraryMapping, Architecture
from mpwn.utils.console import prompt, error, success
from mpwn.utils.system import detect_arch, parse_ldd_output
from mpwn.libc.downloader import (
    list_glibc_versions,
    download_glibc_version,
    download_and_extract_all,
)
from mpwn.libc.version_manager import (
    save_version_list,
    load_version_list,
    find_local_versions,
    find_stored_versions,
    find_libc_in_version,
)
from mpwn.utils.selection import (
    select_version_from_local as select_from_local_matches,
    select_version_from_stored as select_from_stored_matches,
)
from mpwn.core.file_handler import handle_files
from mpwn.core.patcher import patch_program
from mpwn.core.script_generator import generate_scripts


# Legacy class alias for backwards compatibility
class ChalFileInfo:
    """Legacy class for backwards compatibility.

    New code should use ChallengeFileInfo from mpwn.models instead.
    """

    def __init__(self, exe='', ld='', libc='', libs=None, linked_libs=None):
        self._info = ChallengeFileInfo.from_legacy(
            executable=exe,
            ld_editor=ld,
            libc=libc,
            other_libs=libs,
            linked_libs=linked_libs,
        )

    @property
    def Executable(self):
        return str(self._info.executable) if self._info.executable else ''

    @Executable.setter
    def Executable(self, value):
        from pathlib import Path
        self._info.executable = Path(value) if value else None

    @property
    def LD_eDitor(self):
        return str(self._info.ld_loader) if self._info.ld_loader else ''

    @LD_eDitor.setter
    def LD_eDitor(self, value):
        from pathlib import Path
        self._info.ld_loader = Path(value) if value else None

    @property
    def LIBC(self):
        return str(self._info.libc) if self._info.libc else ''

    @LIBC.setter
    def LIBC(self, value):
        from pathlib import Path
        self._info.libc = Path(value) if value else None

    @property
    def OTHERLIBS(self):
        return [lib.to_dict() for lib in self._info.other_libs]

    @OTHERLIBS.setter
    def OTHERLIBS(self, value):
        from pathlib import Path
        self._info.other_libs = []
        if value:
            for lib_dict in value:
                for name, path in lib_dict.items():
                    self._info.other_libs.append(LibraryMapping(
                        name=name,
                        path=Path(path) if path else None
                    ))

    @property
    def LinkedLibs(self):
        return [lib.to_dict() for lib in self._info.linked_libs]

    @LinkedLibs.setter
    def LinkedLibs(self, value):
        from pathlib import Path
        self._info.linked_libs = []
        if value:
            for lib_dict in value:
                for name, path in lib_dict.items():
                    self._info.linked_libs.append(LibraryMapping(
                        name=name,
                        path=Path(path) if path and not path.startswith("(") else None
                    ))

    def __str__(self):
        return str(self._info)


if __name__ == '__main__':
    from mpwn.cli import main
    sys.exit(main())
