#!/usr/bin/env python3
import os
import re
import subprocess
import requests
from datetime import datetime
from bs4 import BeautifulSoup
from prettytable import PrettyTable

__all__ = ['list_glibc_versions', 'download_glibc_version', 'download_and_extract_all']

COMMON_URL = 'https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/'
OLD_URL = 'http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/'
LOCAL_BASE = os.path.expanduser("~/.local/mpwn_libs")
DEBS_DIR = os.path.join(LOCAL_BASE, "debs")
LIBS_DIR = os.path.join(LOCAL_BASE, "libs")

import shutil
import tempfile
import tarfile

def extract_deb(deb_path: str, output_dir: str):
    """
    deb extractor
    """
    if not os.path.isfile(deb_path):
        raise FileNotFoundError(f"{deb_path} not found")

    os.makedirs(output_dir, exist_ok=True)
    tmpdir = tempfile.mkdtemp()
    cwd = os.getcwd()

    try:
        os.chdir(tmpdir)
        print(f"[*] Extracting deb: {deb_path}")
        subprocess.run(["ar", "x", os.path.abspath(deb_path)], check=True)

        data_tar = None
        for name in os.listdir('.'):
            if name.startswith("data.tar"):
                data_tar = name
                break

        if data_tar is None:
            raise RuntimeError("data.tar.* not found in deb package")

        if data_tar.endswith(".zst"):
            print("[*] Detected Zstandard compression")
            try:
                result = subprocess.run(["tar", "--help"], capture_output=True, text=True)
                if "--zstd" in result.stdout:
                    subprocess.run(["tar", "--zstd", "-xf", data_tar], check=True)
                else:
                    subprocess.run(["zstd", "-d", data_tar], check=True)
                    uncompressed = data_tar.replace(".zst", "")
                    with tarfile.open(uncompressed) as tar:
                        tar.extractall()
            except (FileNotFoundError, subprocess.CalledProcessError):
                with open(data_tar, "rb") as f:
                    with tarfile.open(fileobj=f, mode="r:*") as tar:
                        tar.extractall()
        elif data_tar.endswith(".xz"):
            print("[*] Detected XZ compression")
            subprocess.run(["tar", "-xJf", data_tar], check=True)
        elif data_tar.endswith(".gz") or data_tar.endswith(".tgz"):
            print("[*] Detected Gzip compression")
            subprocess.run(["tar", "-xzf", data_tar], check=True)
        else:
            print("[*] Extracting standard tar archive")
            with tarfile.open(data_tar) as tar:
                tar.extractall()

        copied = False
        for src in [
            "lib",
            "lib32",
            "usr/lib",
            "usr/lib32",
            "usr/lib/debug/lib",
            "usr/lib/debug/lib32",
            "usr/lib/debug/.build-id",
        ]:
            src_path = os.path.join(tmpdir, src)
            if os.path.exists(src_path):
                shutil.copytree(src_path, os.path.join(output_dir, os.path.basename(src)), 
                                dirs_exist_ok=True, symlinks=True)
                copied = True

        if not copied:
            raise RuntimeError("No known library directories found in deb.")

        print(f"[+] Extracted to {output_dir}")

    except Exception as e:
        print(f"[!] Extraction failed: {e}")
        # unwind
        try:
            print("[*] Trying alternative extraction method")
            with tarfile.open(deb_path) as tar:
                tar.extractall(output_dir)
            print(f"[+] Successfully extracted with fallback method to {output_dir}")
        except Exception as fallback_e:
            print(f"[Error] Fallback extraction also failed: {fallback_e}")
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmpdir, ignore_errors=True)


def fetch_versions_with_arch(url: str, arch: str) -> list[tuple[str, str]]:
    try:
        content = requests.get(url, timeout=10).text
    except Exception as e:
        print(f"[!] Failed to fetch from {url}: {e}")
        return []

    pattern = rf'libc6_(2\.[0-9]+-[0-9]ubuntu[\d\.]*?)_{arch}\.deb'
    matches = re.findall(pattern, content)
    return [(m, arch) for m in matches]

def list_glibc_versions():
    arch_list = ['amd64', 'i386']
    combined = []

    print("[*] Fetching glibc versions from mirrors...")

    for arch in arch_list:
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
    urls = []
    for base_url in [COMMON_URL, OLD_URL]:
        try:
            resp = requests.get(base_url)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith("libc6_") and href.endswith(".deb"):
                    match = re.match(r'libc6_(2\.[0-9]+-[0-9]ubuntu[\d\.]*)_([a-z0-9]+)\.deb', href)
                    if match:
                        ver, arch = match.groups()
                        urls.append((base_url + href, ver, arch))
        except Exception as e:
            print(f"[!] Failed to fetch URLs from {base_url}: {e}")
    return urls

def download_and_extract_all():
    os.makedirs(DEBS_DIR, exist_ok=True)
    os.makedirs(LIBS_DIR, exist_ok=True)

    urls = fetch_all_glibc_urls()
    for url, ver, arch in urls:
        filename = f"libc6_{ver}_{arch}.deb"
        deb_path = os.path.join(DEBS_DIR, filename)
        extract_path = os.path.join(LIBS_DIR, f"{ver}_{arch}")

        if os.path.exists(extract_path):
            print(f"[+] Already exists: {ver}_{arch}")
            continue

        try:
            print(f"[*] Downloading {filename}...")
            r = requests.get(url)
            r.raise_for_status()
            with open(deb_path, "wb") as f:
                f.write(r.content)

            extract_deb(deb_path, extract_path)
            print(f"[+] Saved {ver}_{arch} to {extract_path}")
        except Exception as e:
            print(f"[!] Failed to process {filename}: {e}")
            
            

def download_glibc_version(ver: str, arch: str):
    filename = f"libc6_{ver}_{arch}.deb"
    deb_path = os.path.join(DEBS_DIR, filename)
    libs_dir = os.path.join(LIBS_DIR, f"{ver}_{arch}")

    if os.path.exists(libs_dir):
        print(f"[+] {ver} already downloaded and extracted.")
        return

    urls = [
        COMMON_URL + filename,
        OLD_URL + filename
    ]

    os.makedirs(DEBS_DIR, exist_ok=True)

    for url in urls:
        print(f"[*] Trying to download from: {url}")
        resp = requests.get(url, stream=True)
        if resp.status_code == 200:
            with open(deb_path, "wb") as f:
                for chunk in resp.iter_content(8192):
                    f.write(chunk)
            os.makedirs(libs_dir, exist_ok=True)
            extract_deb(deb_path, libs_dir)
            print(f"[+] Downloaded and extracted {ver} to {libs_dir}")
            return
        else:
            print(f"[!] Not found at: {url}")

    raise FileNotFoundError(f"{filename} not found in known mirrors.")

