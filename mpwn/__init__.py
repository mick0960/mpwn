"""
MPwn - CTF Pwn Challenge Environment Manager

A tool for managing glibc versions and patching executables
for binary exploitation challenges.
"""

from mpwn.config import __version__
from mpwn.models import ChallengeFileInfo, LibraryMapping, Architecture

__all__ = [
    "__version__",
    "ChallengeFileInfo",
    "LibraryMapping",
    "Architecture",
]
