"""
Backwards compatibility wrapper for libc utilities.

This module re-exports from the new mpwn package structure.
New code should import directly from mpwn.libc instead.
"""

import sys
import os

# Add parent directory to path for package import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Re-export everything from new modules
from mpwn.libc.downloader import (
    list_glibc_versions,
    download_glibc_version,
    download_and_extract_all,
)
from mpwn.libc.extractor import extract_deb
from mpwn.libc.version_manager import (
    save_version_list,
    load_version_list,
    find_local_versions,
    find_stored_versions,
    find_libc_in_version,
)

# For backwards compatibility with `from utils.libc_utils import *`
__all__ = [
    'list_glibc_versions',
    'download_glibc_version',
    'download_and_extract_all',
    'extract_deb',
]
