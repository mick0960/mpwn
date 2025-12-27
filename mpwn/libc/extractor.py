"""
Deb package extractor for MPwn.

Provides functionality to extract glibc libraries from .deb packages.
"""

import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from mpwn.config import LIB_SEARCH_PATHS
from mpwn.utils.console import info


class DebExtractor:
    """Handles extraction of .deb packages.

    This class extracts glibc libraries from Ubuntu .deb packages,
    handling various compression formats (zstd, xz, gz).

    Attributes:
        deb_path: Path to the .deb file
        output_dir: Directory to extract libraries to
    """

    def __init__(self, deb_path: Path, output_dir: Path):
        """Initialize the extractor.

        Args:
            deb_path: Path to the .deb file to extract
            output_dir: Directory to extract libraries to
        """
        self.deb_path = Path(deb_path)
        self.output_dir = Path(output_dir)

    def extract(self) -> None:
        """Execute the full extraction process.

        Raises:
            FileNotFoundError: If deb file doesn't exist
            RuntimeError: If extraction fails
        """
        if not self.deb_path.is_file():
            raise FileNotFoundError(f"{self.deb_path} not found")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        tmpdir = Path(tempfile.mkdtemp())
        original_cwd = os.getcwd()

        try:
            os.chdir(tmpdir)
            info(f"Extracting deb: {self.deb_path}")

            self._extract_ar_archive()
            data_tar = self._find_data_tar(tmpdir)
            self._extract_data_tar(data_tar)
            self._copy_libraries(tmpdir)

            print(f"[+] Extracted to {self.output_dir}")

        except Exception as e:
            print(f"[!] Extraction failed: {e}")
            self._try_fallback_extraction()
        finally:
            os.chdir(original_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _extract_ar_archive(self) -> None:
        """Extract the ar archive from the deb file."""
        subprocess.run(
            ["ar", "x", str(self.deb_path.absolute())],
            check=True
        )

    def _find_data_tar(self, tmpdir: Path) -> Path:
        """Locate the data.tar.* file in the extracted contents.

        Args:
            tmpdir: Temporary directory containing extracted files

        Returns:
            Path to the data tar file

        Raises:
            RuntimeError: If data.tar.* is not found
        """
        for name in os.listdir(tmpdir):
            if name.startswith("data.tar"):
                return tmpdir / name

        raise RuntimeError("data.tar.* not found in deb package")

    def _extract_data_tar(self, data_tar: Path) -> None:
        """Extract data tarball based on compression type.

        Args:
            data_tar: Path to the data tar file
        """
        suffix = data_tar.suffix

        if suffix == ".zst":
            self._extract_zstd(data_tar)
        elif suffix == ".xz":
            info("Detected XZ compression")
            subprocess.run(["tar", "-xJf", str(data_tar)], check=True)
        elif suffix in (".gz", ".tgz"):
            info("Detected Gzip compression")
            subprocess.run(["tar", "-xzf", str(data_tar)], check=True)
        else:
            info("Extracting standard tar archive")
            with tarfile.open(data_tar) as tar:
                tar.extractall()

    def _extract_zstd(self, data_tar: Path) -> None:
        """Extract a zstd compressed tar file.

        Args:
            data_tar: Path to the .tar.zst file
        """
        info("Detected Zstandard compression")

        # Try using tar with --zstd option first
        try:
            result = subprocess.run(
                ["tar", "--help"],
                capture_output=True,
                text=True
            )
            if "--zstd" in result.stdout:
                subprocess.run(
                    ["tar", "--zstd", "-xf", str(data_tar)],
                    check=True
                )
                return
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        # Fall back to zstd command
        try:
            subprocess.run(["zstd", "-d", str(data_tar)], check=True)
            uncompressed = str(data_tar).replace(".zst", "")
            with tarfile.open(uncompressed) as tar:
                tar.extractall()
            return
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

        # Final fallback - try python tarfile directly
        with open(data_tar, "rb") as f:
            with tarfile.open(fileobj=f, mode="r:*") as tar:
                tar.extractall()

    def _copy_libraries(self, tmpdir: Path) -> None:
        """Copy library directories from tmpdir to output.

        Args:
            tmpdir: Temporary directory containing extracted files

        Raises:
            RuntimeError: If no library directories are found
        """
        copied = False

        for src in LIB_SEARCH_PATHS:
            src_path = tmpdir / src
            if src_path.exists():
                dest_path = self.output_dir / src_path.name
                shutil.copytree(
                    src_path,
                    dest_path,
                    dirs_exist_ok=True,
                    symlinks=True
                )
                copied = True

        if not copied:
            raise RuntimeError("No known library directories found in deb.")

    def _try_fallback_extraction(self) -> None:
        """Attempt fallback extraction method."""
        try:
            info("Trying alternative extraction method")
            with tarfile.open(self.deb_path) as tar:
                tar.extractall(self.output_dir)
            print(f"[+] Successfully extracted with fallback method to {self.output_dir}")
        except Exception as fallback_e:
            print(f"[!] Fallback extraction also failed: {fallback_e}")


def extract_deb(deb_path: str | Path, output_dir: str | Path) -> None:
    """Extract a deb package to the specified directory.

    This is a convenience function wrapping the DebExtractor class.

    Args:
        deb_path: Path to the .deb file
        output_dir: Directory to extract to
    """
    extractor = DebExtractor(Path(deb_path), Path(output_dir))
    extractor.extract()
