"""
Centralized configuration and constants for MPwn.

All path constants and URLs are defined here to ensure consistency
across all modules. This eliminates the previous duplication between
mpwn.py and utils/libc_utils.py.
"""

from pathlib import Path
from typing import Final

# Version
__version__: Final[str] = "2.0.0"

# Mirror URLs for glibc packages
MIRROR_URLS: Final[tuple[str, ...]] = (
    "https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/",
    "http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/",
)

# Convenience aliases (backwards compatible)
COMMON_URL: Final[str] = MIRROR_URLS[0]
OLD_URL: Final[str] = MIRROR_URLS[1]

# Local storage paths
LOCAL_BASE: Final[Path] = Path.home() / ".local" / "mpwn_libs"
DEBS_DIR: Final[Path] = LOCAL_BASE / "debs"
LIBS_DIR: Final[Path] = LOCAL_BASE / "libs"

# User configuration paths
CONFIG_DIR: Final[Path] = Path.home() / ".config" / "mpwn"
VERSION_LIST_PATH: Final[Path] = CONFIG_DIR / "list"
TEMPLATE_PATH: Final[Path] = CONFIG_DIR / "template.py"
USER_CONFIG_PATH: Final[Path] = CONFIG_DIR / "config.json"

# Regex patterns for parsing
LIBC_DEB_PATTERN: Final[str] = r"libc6_(2\.[0-9]+-[0-9]ubuntu[\d\.]*?)_{arch}\.deb"
LIBC_DEB_PATTERN_GENERIC: Final[str] = r"libc6_(2\.[0-9]+-[0-9]ubuntu[\d\.]*)_([a-z0-9]+)\.deb"

# Supported architectures
SUPPORTED_ARCHITECTURES: Final[tuple[str, ...]] = ("amd64", "i386")

# Library search paths within extracted debs
LIB_SEARCH_PATHS: Final[tuple[str, ...]] = (
    "lib",
    "lib32",
    "usr/lib",
    "usr/lib32",
    "usr/lib/debug/lib",
    "usr/lib/debug/lib32",
    "usr/lib/debug/.build-id",
)

# Patterns to identify LD loader files
LD_PATTERNS: Final[tuple[str, ...]] = ("ld-", "ld.so", "ld-linux", "linux-gate")


def ensure_directories() -> None:
    """Create all required directories if they don't exist."""
    DEBS_DIR.mkdir(parents=True, exist_ok=True)
    LIBS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
