"""
Command-line interface for MPwn.

Provides the main entry point and argument parsing for the mpwn command.
"""

import argparse
import os
import sys

from mpwn.config import DEBS_DIR, LIBS_DIR, __version__, ensure_directories
from mpwn.core.patcher import patch_program
from mpwn.libc.downloader import list_glibc_versions, download_and_extract_all
from mpwn.libc.version_manager import save_version_list


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog="mpwn",
        description="MPwn: Environment Configuration Tool for Pwn Challenges",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mpwn ./challenge              # Patch using current directory libs
  mpwn ./challenge 2.31         # Patch with specific glibc version
  mpwn ./challenge 2.31-1ubuntu3  # Patch with exact version
  mpwn --fetch                  # List available glibc versions
  mpwn --fetch-all              # Download all glibc libraries
""",
    )

    parser.add_argument(
        "exe",
        nargs="?",
        help="Target executable file",
    )

    parser.add_argument(
        "libc_version",
        nargs="?",
        help="Glibc version to use (e.g., 2.31 or 2.40-1ubuntu3)",
    )

    parser.add_argument(
        "--fetch",
        action="store_true",
        help="List available glibc versions and save to list",
    )

    parser.add_argument(
        "--fetch-all",
        action="store_true",
        help="Download all available glibc libraries and update list",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def handle_fetch() -> None:
    """Handle the --fetch command."""
    print("[*] Fetching available glibc versions...")
    versions = list_glibc_versions()
    save_version_list(versions)


def handle_fetch_all() -> None:
    """Handle the --fetch-all command."""
    print("[*] Downloading all available glibc libraries...")
    download_and_extract_all()
    print("[+] All glibc libraries downloaded and extracted")

    # Update version list from local files
    print("[*] Updating version list...")
    versions: list[tuple[str, str]] = []

    for entry in LIBS_DIR.iterdir():
        if entry.is_dir() and "_" in entry.name:
            parts = entry.name.split("_")
            version = "_".join(parts[:-1])
            arch = parts[-1]
            versions.append((version, arch))

    save_version_list(versions)


def print_usage() -> None:
    """Print usage information."""
    print("MPwn: Environment Configuration Tool for Pwn Challenges")
    print()
    print("Usage:")
    print("  mpwn [options] <executable> [libc_version]")
    print()
    print("Options:")
    print("  --fetch       List available glibc versions and save to list")
    print("  --fetch-all   Download all available glibc libraries and update list")
    print("  --version     Show version information")
    print()
    print("Examples:")
    print("  mpwn ./challenge 2.31            # Patch with specific glibc version")
    print("  mpwn ./challenge 2.31-1ubuntu3   # Patch with exact version")
    print("  mpwn ./challenge                 # Use current directory libs")


def main(args: list[str] | None = None) -> int:
    """Main entry point for the CLI.

    Args:
        args: Command-line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    # Ensure directories exist
    ensure_directories()

    parser = create_parser()
    parsed = parser.parse_args(args)

    try:
        if parsed.fetch:
            handle_fetch()
        elif parsed.fetch_all:
            handle_fetch_all()
        elif parsed.exe:
            patch_program(parsed.exe, parsed.libc_version)
        else:
            print_usage()

        return 0

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        return 130

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
