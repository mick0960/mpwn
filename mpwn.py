#!/usr/bin/env python3
import argparse
import os
import json
import datetime
from jinja2 import Template
from shutil import copy2
from utils.libc_utils import *
import subprocess
import re
import magic
from prettytable import PrettyTable
import fnmatch

# ------------------- Glibc Download Constants & Functions ------------------- #

COMMON_URL = 'https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/'
OLD_URL = 'http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/'
LOCAL_BASE = os.path.expanduser("~/.local/mpwn_libs")
DEBS_DIR = os.path.join(LOCAL_BASE, "debs")
LIBS_DIR = os.path.join(LOCAL_BASE, "libs")

# ------------------- Utility Classes & Functions ------------------- #

class ChalFileInfo:
    def __init__(self, exe='', ld='', libc='', libs=None, linked_libs=None):
        self.Executable = exe or ''
        self.LD_eDitor = ld or ''
        self.LIBC = libc or ''
        self.OTHERLIBS = libs if libs is not None else []
        self.LinkedLibs = linked_libs if linked_libs is not None else []

    def __str__(self):
        info = [
            f"Executable: {self.Executable}",
            f"LD Editor: {self.LD_eDitor}",
            f"LIBC: {self.LIBC}",
            "Other Libs:"
        ]
        for lib in self.OTHERLIBS:
            for name, path in lib.items():
                info.append(f"  {name} -> {path}")
        info.append("Linked Libs:")
        for entry in self.LinkedLibs:
            for name, path in entry.items():
                info.append(f"  {name} => {path}")
        return '\n'.join(info)


def prompt(message: str = "") -> bool:
    ans = input(message + " (Y/y or N/n): ")
    return ans.lower() != 'n'

def error(message: str = ""):
    print(f"[ERROR] {message}")
    exit(1)

def success(message: str = ""):
    print(f"[Success] {message}")

def detect_arch(executable_path: str) -> str:
    """Detect the architecture of the executable using the file command"""
    try:
        output = subprocess.check_output(["file", executable_path], text=True)
        if "ELF 32-bit" in output:
            return "i386"
        elif "ELF 64-bit" in output:
            return "amd64"
        else:
            error(f"Unsupported architecture for {executable_path}")
    except subprocess.CalledProcessError:
        error("Failed to detect executable architecture")
    return "amd64"  # Default to amd64

def find_libc_in_version(version: str, arch: str) -> tuple:
    """Find libc and ld paths for a given version and architecture"""
    base_dir = os.path.join(LIBS_DIR, f"{version}_{arch}")
    if not os.path.exists(base_dir):
        return None, None
    
    libc_path = None
    ld_path = None
    
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file == "libc.so.6":
                libc_path = os.path.join(root, file)
            elif file.startswith("ld") and (file.endswith(".so.2") or file.endswith(".so")):
                ld_path = os.path.join(root, file)
    
    return libc_path, ld_path

def save_version_list(versions: list):
    """Save the list of glibc versions to ~/.config/mpwn/list"""
    config_dir = os.path.join(os.path.expanduser("~"), ".config", "mpwn")
    os.makedirs(config_dir, exist_ok=True)
    list_path = os.path.join(config_dir, "list")
    
    with open(list_path, "w") as f:
        for ver, arch in versions:
            f.write(f"{ver}_{arch}\n")
    
    print(f"[+] Saved {len(versions)} versions to {list_path}")

def load_version_list() -> list:
    """Load the list of glibc versions from ~/.config/mpwn/list"""
    list_path = os.path.join(os.path.expanduser("~"), ".config", "mpwn", "list")
    if not os.path.exists(list_path):
        return []
    
    versions = []
    with open(list_path, "r") as f:
        for line in f:
            parts = line.strip().split('_')
            if len(parts) >= 2:
                version = '_'.join(parts[:-1])
                arch = parts[-1]
                versions.append((version, arch))
    return versions

def find_local_versions(pattern: str, arch: str) -> list:
    """Find local libc versions matching the pattern and architecture"""
    matches = []
    for entry in os.listdir(LIBS_DIR):
        if '_' in entry:
            ver_part, a = entry.rsplit('_', 1)
            if a == arch and fnmatch.fnmatch(ver_part, f"*{pattern}*"):
                matches.append(ver_part)
    return matches

def select_from_local_matches(matches: list, arch: str) -> str:
    """Prompt user to select from local matching versions"""
    table = PrettyTable()
    table.field_names = ["Index", "Version", "Arch"]
    for idx, ver in enumerate(matches, 1):
        table.add_row([idx, ver, arch])
    
    print("\nMatching local versions:")
    print(table)
    
    while True:
        try:
            choice = int(input("\nSelect a version by index (0 to skip): "))
            if choice == 0:
                return None
            if 1 <= choice <= len(matches):
                return matches[choice-1]
            print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a number.")

def find_stored_versions(pattern: str, arch: str) -> list:
    """Find stored versions matching the pattern and architecture"""
    stored_versions = load_version_list()
    return [(ver, a) for ver, a in stored_versions if a == arch and pattern in ver]

def select_from_stored_matches(matches: list) -> str:
    """Prompt user to select from stored matching versions"""
    table = PrettyTable()
    table.field_names = ["Index", "Version", "Arch"]
    for idx, (ver, arch) in enumerate(matches, 1):
        table.add_row([idx, ver, arch])
    
    print("\nMatching stored versions:")
    print(table)
    
    while True:
        try:
            choice = int(input("\nSelect a version to download (0 to skip): "))
            if choice == 0:
                return None
            if 1 <= choice <= len(matches):
                return matches[choice-1][0]
            print("Invalid choice. Please try again.")
        except ValueError:
            print("Please enter a number.")

# ------------------- Core ------------------- #

def parse_ldd_output(executable_path: str):
    result = []
    try:
        output = subprocess.check_output(["ldd", executable_path], text=True)
        for line in output.splitlines():
            match = re.match(r'\s*(\S+)\s+=>\s+(\S+)', line)
            if match:
                libname, libpath = match.group(1), match.group(2)
                if any(x in libname for x in ("ld-", "ld.so", "ld-linux", "linux-gate")):
                    continue
                result.append({libname: libpath})
            else:
                tokens = line.strip().split()
                if len(tokens) == 2 and tokens[1].startswith('('):
                    libname = tokens[0]
                    if any(x in libname for x in ("ld-", "ld.so", "ld-linux", "linux-gate")):
                        continue
                    result.append({libname: tokens[1]})
    except subprocess.CalledProcessError:
        error("Can't parse ldd's output!")
    return result

def handle_files(exe: str="", libc_version: str=None, arch: str=None):
    temp = ChalFileInfo()
    mime = magic.Magic(mime=True)
    
    if exe:
        if prompt(f"It seems that you want {exe} to be the challenge file?"):
            temp.Executable = os.path.abspath(exe)
                
    if libc_version and arch:
        libc_path, ld_path = find_libc_in_version(libc_version, arch)
        if libc_path:
            temp.LIBC = libc_path
            success(f"Using libc: {libc_path}")
        if ld_path:
            temp.LD_eDitor = ld_path
            success(f"Using ld: {ld_path}")
        
        for file in os.listdir('.'):
            if os.path.isdir(file):
                continue
                
            file_path = os.path.abspath(file)
            file_type = mime.from_file(file_path)
            
            if file_type == 'application/x-sharedlib':
                if 'libc' not in file.lower() and 'ld' not in file.lower():
                    temp.OTHERLIBS.append({file: file_path})
                
                    
    else:
        for file in os.listdir('.'):
            if os.path.isdir(file):
                continue
                
            file_path = os.path.abspath(file)
            file_type = mime.from_file(file_path)
            
            if 'executable' in file_type and not temp.Executable:
                if prompt(f"Choosing {file} as your executable file?"):
                    temp.Executable = file_path
            elif file_type == 'application/x-sharedlib':
                if 'libc' in file.lower() and not temp.LIBC:
                    temp.LIBC = file_path
                elif 'ld' in file.lower() and not temp.LD_eDitor:
                    temp.LD_eDitor = file_path
                else:
                    temp.OTHERLIBS.append({file: file_path})
                
    if not temp.Executable:
        error("No executable file found!")
        
    temp.LinkedLibs = parse_ldd_output(temp.Executable)
    return temp

def patch_program(exe: str="", libc_version: str=None):
    """
    Patch program with specified glibc version or use workdir's glibc if available.
    If libc_version is provided, it will search for local and stored versions,
    specified glibc version will be use or download as the final version is given.
    If no version is specified, it will use the current working directory's libs.
    """
    if not os.path.exists(f"./{exe}"):
        error("Unkown executable!")
    
    arch = detect_arch(exe) if exe else "amd64"
    final_version = None
    
    if libc_version:
        local_matches = find_local_versions(libc_version, arch)
        
        if local_matches:
            final_version = select_from_local_matches(local_matches, arch)
            if final_version:
                print(f"[*] Selected local version: {final_version} for {arch}")
        else:
            print(f"[*] No local versions found matching '{libc_version}' for {arch}")
        
        
        if not final_version:
            stored_matches = find_stored_versions(libc_version, arch)
            
            if stored_matches:
                selected = select_from_stored_matches(stored_matches)
                if selected:
                    print(f"[*] Selected stored version: {selected} for {arch}")
                    final_version = selected
            else:
                print(f"[*] No stored versions found matching '{libc_version}' for {arch}")
                   
        if final_version:
            version_dir = os.path.join(LIBS_DIR, f"{final_version}_{arch}")
            if not os.path.exists(version_dir):
                print(f"[*] Downloading glibc {final_version} for {arch}...")
                try:
                    download_glibc_version(final_version, arch)
                    success(f"Downloaded glibc {final_version} for {arch}")
                except Exception as e:
                    error(f"Failed to download glibc: {e}")
        else:
            print(f"[*] Using dir-provided version for {exe}")
    
    if final_version:
        version_dir = os.path.join(LIBS_DIR, f"{final_version}_{arch}")
        if not os.path.exists(version_dir):
            print(f"[*] Downloading glibc {final_version} for {arch}...")
            try:
                download_glibc_version(final_version, arch)
                success(f"Downloaded glibc {final_version} for {arch}")
            except Exception as e:
                error(f"Failed to download glibc: {e}")
    
    chal = handle_files(exe, final_version, arch)
    
    if chal.LD_eDitor and chal.LIBC:
        print('\nCurrent Info:\n' + str(chal) + '\n')
        
        if prompt("Apply patches?"):
            try:
                backup_path = chal.Executable + ".bak"
                copy2(chal.Executable, backup_path)
                success(f"Backup success: {backup_path}")
                
                lib_map = {"libc.so.6": chal.LIBC} if chal.LIBC else {}
                for lib in chal.OTHERLIBS:
                    lib_map.update(lib)
                    
                if chal.LD_eDitor:
                    subprocess.run(["patchelf", "--set-interpreter", chal.LD_eDitor, chal.Executable])
                    success(f"Set interpreter to: {chal.LD_eDitor}")
                    
                for entry in chal.LinkedLibs:
                    for libname, _ in entry.items():
                        if libname in lib_map:
                            subprocess.run(["patchelf", "--replace-needed", libname, lib_map[libname], chal.Executable], check=True)
                            success(f"Replaced {libname} --> {lib_map[libname]}")
                            
            except subprocess.CalledProcessError as e:
                error(f"Patching failed! {e}")
        
    generate_scripts(chal)

def generate_scripts(chal: ChalFileInfo):
    template_dir = os.path.join(os.path.expanduser("~"), ".config", "mpwn")
    template_path = os.path.join(template_dir, "template.py")
    config_path = os.path.join(template_dir, "config.json")

    if not os.path.isfile(template_path):
        error("Missing template file")
    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    config = {}
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

    config.update({
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filename": chal.Executable,
        "libcname": chal.LIBC
    })

    try:
        rendered = Template(template_content).render(config)
        output_path = f"{config.get('script_name', 'exploit.py')}"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)
        success(f"Script generated: {output_path}")
    except Exception as e:
        error(f"Render failed: {str(e)}")

# ------------------- Main ------------------- #

if __name__ == '__main__':
    os.makedirs(DEBS_DIR, exist_ok=True)
    os.makedirs(LIBS_DIR, exist_ok=True)
    
    parser = argparse.ArgumentParser(description='M-Pwn: Tool for pwn')
    parser.add_argument('exe', nargs='?', help='Target executable file')
    parser.add_argument('libc_version', nargs='?', help='Glibc version to use (e.g., 2.31 or 2.40-1ubuntu3)')
    parser.add_argument('--fetch', action='store_true', help='List available glibc versions and save to list')
    parser.add_argument('--fetch-all', action='store_true', help='Download all available glibc libraries and update list')
    args = parser.parse_args()

    if args.fetch:
        print("[*] Fetching available glibc versions...")
        versions = list_glibc_versions()
        save_version_list(versions)
    elif args.fetch_all:
        print("[*] Downloading all available glibc libraries...")
        download_and_extract_all()
        print("[+] All glibc libraries downloaded and extracted")
        
        print("[*] Updating version list...")
        versions = []
        for entry in os.listdir(LIBS_DIR):
            if '_' in entry:
                parts = entry.split('_')
                version = '_'.join(parts[:-1])
                arch = parts[-1]
                versions.append((version, arch))
        save_version_list(versions)
    else:
        if not args.exe:
            print("M-Pwn: Tool for pwn\nUsage：\n  mpwn [options] <executable> [libc_version]      # do patch for executable")
            print("Options:")
            print("  --fetch       List available glibc versions and save to list")
            print("  --fetch-all   Download all available glibc libraries and update list")
            print("\nExamples:")
            print("  mpwn ./challenge 2.31 or 2.31-1ubuntu3     # specific glibc version")
            print("  mpwn ./challenge               # using current workdir's libs")
        else:
            patch_program(args.exe, args.libc_version)