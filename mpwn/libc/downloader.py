"""
Glibc downloader for MPwn.

Provides functionality to download glibc packages from Ubuntu mirrors.
"""

import re
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from prettytable import PrettyTable

from mpwn.config import (
    COMMON_URL,
    OLD_URL,
    MIRROR_URLS,
    DEBS_DIR,
    LIBS_DIR,
    LIBC_DEB_PATTERN_GENERIC,
    SUPPORTED_ARCHITECTURES,
)
from mpwn.libc.extractor import extract_deb
from mpwn.utils.console import info


def fetch_versions_with_arch(url: str, arch: str) -> list[tuple[str, str]]:
    """Fetch available glibc versions for a specific architecture.

    Args:
        url: Mirror URL to fetch from
        arch: Architecture to filter for (e.g., 'amd64', 'i386')

    Returns:
        List of (version, arch) tuples
    """
    try:
        content = requests.get(url, timeout=10).text
    except requests.Timeout:
        print(f"[!] Timeout fetching from {url}")
        return []
    except requests.ConnectionError as e:
        print(f"[!] Connection error to {url}: {e}")
        return []
    except Exception as e:
        print(f"[!] Unexpected error fetching from {url}: {e}")
        return []

    pattern = rf"libc6_(2\.[0-9]+-[0-9]ubuntu[\d\.]*?)_{arch}\.deb"
    matches = re.findall(pattern, content)
    return [(m, arch) for m in matches]


def list_glibc_versions() -> list[tuple[str, str]]:
    """List all available glibc versions from mirrors.

    Fetches available versions from both primary and fallback mirrors
    for all supported architectures.

    Returns:
        Sorted list of unique (version, arch) tuples
    """
    combined: list[tuple[str, str]] = []

    info("Fetching glibc versions from mirrors...")

    for arch in SUPPORTED_ARCHITECTURES:
        combined += fetch_versions_with_arch(COMMON_URL, arch)
        combined += fetch_versions_with_arch(OLD_URL, arch)

    if not combined:
        print("[!] No versions found.")
        return []

    unique_versions = sorted(set(combined), key=lambda x: (x[0], x[1]))

    table = PrettyTable()
    table.field_names = ["Version", "Arch"]
    for ver, arch in unique_versions:
        table.add_row([ver, arch])

    print(table)
    return unique_versions


def fetch_all_glibc_urls() -> list[tuple[str, str, str]]:
    """Fetch all available glibc download URLs.

    Returns:
        List of (url, version, arch) tuples
    """
    urls: list[tuple[str, str, str]] = []

    for base_url in MIRROR_URLS:
        try:
            resp = requests.get(base_url, timeout=15)
            soup = BeautifulSoup(resp.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("libc6_") and href.endswith(".deb"):
                    match = re.match(LIBC_DEB_PATTERN_GENERIC, href)
                    if match:
                        ver, arch = match.groups()
                        urls.append((base_url + href, ver, arch))
        except Exception as e:
            print(f"[!] Failed to fetch URLs from {base_url}: {e}")

    return urls


def download_and_extract_all() -> None:
    """Download and extract all available glibc versions.

    Downloads all versions from mirrors and extracts them to the
    local library directory.
    """
    DEBS_DIR.mkdir(parents=True, exist_ok=True)
    LIBS_DIR.mkdir(parents=True, exist_ok=True)

    urls = fetch_all_glibc_urls()

    for url, ver, arch in urls:
        filename = f"libc6_{ver}_{arch}.deb"
        deb_path = DEBS_DIR / filename
        extract_path = LIBS_DIR / f"{ver}_{arch}"

        if extract_path.exists():
            print(f"[+] Already exists: {ver}_{arch}")
            continue

        try:
            info(f"Downloading {filename}...")
            r = requests.get(url, timeout=60)
            r.raise_for_status()

            with open(deb_path, "wb") as f:
                f.write(r.content)

            extract_deb(deb_path, extract_path)
            print(f"[+] Saved {ver}_{arch} to {extract_path}")
        except Exception as e:
            print(f"[!] Failed to process {filename}: {e}")


def download_glibc_version(ver: str, arch: str) -> None:
    """Download and extract a specific glibc version.

    Args:
        ver: Version string (e.g., '2.31-0ubuntu9.9')
        arch: Architecture (e.g., 'amd64')

    Raises:
        FileNotFoundError: If version not found in any mirror
    """
    filename = f"libc6_{ver}_{arch}.deb"
    deb_path = DEBS_DIR / filename
    libs_dir = LIBS_DIR / f"{ver}_{arch}"

    if libs_dir.exists():
        print(f"[+] {ver} already downloaded and extracted.")
        return

    urls = [COMMON_URL + filename, OLD_URL + filename]

    DEBS_DIR.mkdir(parents=True, exist_ok=True)

    for url in urls:
        info(f"Trying to download from: {url}")
        try:
            resp = requests.get(url, stream=True, timeout=60)
            if resp.status_code == 200:
                with open(deb_path, "wb") as f:
                    for chunk in resp.iter_content(8192):
                        f.write(chunk)

                libs_dir.mkdir(parents=True, exist_ok=True)
                extract_deb(deb_path, libs_dir)
                print(f"[+] Downloaded and extracted {ver} to {libs_dir}")
                return
            else:
                print(f"[!] Not found at: {url}")
        except requests.Timeout:
            print(f"[!] Timeout downloading from: {url}")
        except Exception as e:
            print(f"[!] Error downloading from {url}: {e}")

    raise FileNotFoundError(f"{filename} not found in known mirrors.")
