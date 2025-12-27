"""
PWN helper utilities for exploit development.

This module provides commonly used helper functions for CTF pwn challenges,
including debugging, address leaking, and connection management.
"""

import inspect
from typing import Optional, Union, List, Dict, Any

try:
    from pwn import *
except ImportError:
    raise ImportError(
        "pwntools is required for pwn_helpers. Install it with: pip install pwntools"
    )


# Global variables that will be set by the exploit script
_elf = None
_libc = None
_process = None


def setup(process_obj, elf_obj, libc_obj=None):
    """
    Setup global objects for simplified usage.
    This allows using shortcuts and debug functions without passing objects.

    Args:
        process_obj: Process object
        elf_obj: ELF object for the executable
        libc_obj: ELF object for libc (optional)

    Example:
        p = conn("./challenge", "", 0)
        setup(p, elf, libc)
        # Now you can use: sla(), debug(0x1234), etc.
    """
    global _elf, _libc, _process
    _process = process_obj
    _elf = elf_obj
    _libc = libc_obj


def set_elf(elf_obj):
    """Set the global ELF object."""
    global _elf
    _elf = elf_obj


def set_libc(libc_obj):
    """Set the global libc object."""
    global _libc
    _libc = libc_obj


def set_process(process_obj):
    """Set the global process object."""
    global _process
    _process = process_obj


def get_process():
    """Get the current process object."""
    return _process


# ================== Connection Management ==================


def conn(
    elf_name: str = "",
    host: str = "",
    port: int = 0,
    argv: List[str] = None,
    env: Dict[str, str] = None,
):
    """
    Create a connection to local process or remote server.

    Args:
        elf_name: Path to the executable
        host: Remote host (if using remote connection)
        port: Remote port (if using remote connection)
        argv: Additional arguments for process
        env: Environment variables for process

    Returns:
        Process or Remote connection object
    """
    if argv is None:
        argv = []
    if env is None:
        env = {}

    if args.REMOTE or (host and port):
        return remote(host, port)
    return process([elf_name] + argv, env=env)


# ================== Shortcuts ==================


class PwnShortcuts:
    """
    Wrapper class that provides shortcut methods for a process.
    Automatically binds shortcuts to the process object.
    """

    def __init__(self, process_obj):
        self.p = process_obj

    def sla(self, d, c):
        """Send line after receiving delimiter"""
        return self.p.sendlineafter(d, c)

    def sda(self, d, c):
        """Send data after receiving delimiter"""
        return self.p.sendafter(d, c)

    def sl(self, c):
        """Send line"""
        return self.p.sendline(c)

    def sd(self, c):
        """Send data"""
        return self.p.send(c)

    def ru(self, d, **kw):
        """Receive until delimiter"""
        return self.p.recvuntil(d, **kw)

    def rl(self):
        """Receive line"""
        return self.p.recvline()

    def rc(self, n):
        """Receive n bytes"""
        return self.p.recv(n)


def bind_shortcuts(process_obj):
    """
    Bind shortcut methods directly to the process object.
    This allows using p.sla(), p.sl(), etc.

    Args:
        process_obj: Process object to bind shortcuts to

    Returns:
        The same process object with shortcuts bound
    """
    shortcuts = PwnShortcuts(process_obj)
    process_obj.sla = shortcuts.sla
    process_obj.sda = shortcuts.sda
    process_obj.sl = shortcuts.sl
    process_obj.sd = shortcuts.sd
    process_obj.ru = shortcuts.ru
    process_obj.rl = shortcuts.rl
    process_obj.rc = shortcuts.rc
    return process_obj


# ================== Global Shortcuts ==================


def sla(d, c):
    """Send line after delimiter using global process"""
    if _process is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    return _process.sendlineafter(d, c)


def sda(d, c):
    """Send data after delimiter using global process"""
    if _process is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    return _process.sendafter(d, c)


def sl(c):
    """Send line using global process"""
    if _process is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    return _process.sendline(c)


def sd(c):
    """Send data using global process"""
    if _process is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    return _process.send(c)


def ru(d, **kw):
    """Receive until delimiter using global process"""
    if _process is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    return _process.recvuntil(d, **kw)


def rl():
    """Receive line using global process"""
    if _process is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    return _process.recvline()


def rc(n):
    """Receive n bytes using global process"""
    if _process is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    return _process.recv(n)


# ================== Address Leak ==================


def leak64(process_obj=None, prefix: bytes = b"\x7f", length: int = 6) -> int:
    """
    Leak 64-bit address ending with prefix.

    Args:
        process_obj: Process object to receive from (optional, uses global if not provided)
        prefix: Expected prefix bytes (default: b'\x7f' for stack addresses)
        length: Number of bytes to capture (default: 6)

    Returns:
        Unpacked 64-bit address

    Example:
        libc_leak = leak64(p, b'\x7f', 6)  # Explicit process
        libc_leak = leak64(b'\x7f', 6)     # Use global process
    """
    p = process_obj if process_obj is not None else _process
    if p is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    data = p.recvuntil(prefix)[-length:]
    return u64(data.ljust(8, b"\x00"))


def leak32(process_obj=None, prefix: bytes = b"\xf7", length: int = 4) -> int:
    """
    Leak 32-bit address ending with prefix.

    Args:
        process_obj: Process object to receive from (optional, uses global if not provided)
        prefix: Expected prefix bytes (default: b'\xf7' for i386 addresses)
        length: Number of bytes to capture (default: 4)

    Returns:
        Unpacked 32-bit address

    Example:
        libc_leak = leak32(p, b'\xf7', 4)  # Explicit process
        libc_leak = leak32(b'\xf7', 4)     # Use global process
    """
    p = process_obj if process_obj is not None else _process
    if p is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    data = p.recvuntil(prefix)[-length:]
    return u32(data)


def leak(name: str, addr: int) -> int:
    """
    Log leaked address with name.

    Args:
        name: Name/description of the leaked address
        addr: The address value

    Returns:
        The address (for chaining)

    Example:
        libc_base = leak('libc_base', libc_leak - libc.symbols['__libc_start_main'])
    """
    log.success(f"{name}: {hex(addr)}")
    return addr


def lg(val: Any) -> None:
    """
    Auto-detect variable name and log its value.

    Args:
        val: Variable to log (int or any other type)

    Example:
        libc_base = 0x7ffff7a00000
        lg(libc_base)  # Output: [+] libc_base = 0x7ffff7a00000
    """
    frame = inspect.currentframe().f_back
    names = {id(v): k for k, v in frame.f_locals.items()}
    name = names.get(id(val), "value")
    if isinstance(val, int):
        log.success(f"{name} = {hex(val)}")
    else:
        log.success(f"{name} = {val}")


# ================== Debug ==================


def debug(
    bp: Optional[Union[int, str, List, Dict]] = None,
    process_obj=None,
    elf_obj=None,
    libc_obj=None,
    script: str = "",
    pause_after: bool = True,
) -> None:
    """
    Attach GDB with breakpoints.

    Args:
        bp: Breakpoint(s) - supports multiple formats:
            - int/hex: Address or offset (auto-detect PIE)
            - str: Symbol name, hex string "0x1234", or raw gdb command
            - list: Multiple breakpoints
            - dict: {'elf': [...], 'libc': [...]} for different bases
        process_obj: Process object to attach to (optional, uses global if not provided)
        elf_obj: ELF object for the executable (optional, uses global if not provided)
        libc_obj: ELF object for libc (optional, uses global if not provided)
        script: Additional GDB commands to execute
        pause_after: Whether to pause after attach

    Examples:
        debug(0x1234)                    # Break at offset 0x1234 (PIE auto)
        debug("main")                    # Break at symbol
        debug([0x1234, "vuln", 0x5678])  # Multiple breakpoints
        debug({'elf': [0x1234], 'libc': [0x5678]})  # Different bases
        debug(0x1234, script="set $a=1") # With extra gdb commands
    """
    # Use global objects if not provided
    p = process_obj if process_obj is not None else _process
    elf = elf_obj if elf_obj is not None else _elf
    libc = libc_obj if libc_obj is not None else _libc

    if p is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")
    if elf is None:
        raise RuntimeError("ELF not set. Call setup(p, elf, libc) first.")

    if args.REMOTE:
        return

    gdbscript_lines = []

    # Get bases
    libs = p.libs()
    elf_base = libs.get(p.elf.path, 0) if elf.pie else 0
    libc_base = libs.get(libc.path, 0) if libc else 0

    def format_bp(b, base=0):
        """Format a single breakpoint"""
        if isinstance(b, int):
            # Integer: treat as offset if PIE, else as address
            if base or elf.pie:
                return f"b *{hex(base + b)}"
            return f"b *{hex(b)}"
        elif isinstance(b, str):
            # String: check if hex, symbol, or raw command
            b = b.strip()
            if b.startswith("0x") or b.startswith("0X"):
                addr = int(b, 16)
                if base or elf.pie:
                    return f"b *{hex(base + addr)}"
                return f"b *{hex(addr)}"
            elif b.startswith("b ") or b.startswith("break "):
                return b  # Raw gdb command
            else:
                return f"b {b}"  # Symbol name
        return str(b)

    def process_bps(bps, base=0):
        """Process breakpoint list"""
        if bps is None:
            return []
        if not isinstance(bps, list):
            bps = [bps]
        return [format_bp(b, base) for b in bps]

    # Handle different bp formats
    if isinstance(bp, dict):
        # Dict format: {'elf': [...], 'libc': [...]}
        if "elf" in bp:
            gdbscript_lines.extend(process_bps(bp["elf"], elf_base))
        if "libc" in bp:
            gdbscript_lines.extend(process_bps(bp["libc"], libc_base))
        # Other keys treated as raw breakpoints
        for key in bp:
            if key not in ("elf", "libc"):
                gdbscript_lines.extend(process_bps(bp[key]))
    else:
        gdbscript_lines.extend(process_bps(bp, elf_base))

    # Add custom script
    if script:
        gdbscript_lines.append(script)

    # Add continue command if breakpoints set
    if gdbscript_lines:
        gdbscript_lines.append("c")

    gdb.attach(p, gdbscript="\n".join(gdbscript_lines))

    if pause_after:
        pause()


def bp(offset: int, elf_obj=None, process_obj=None) -> int:
    """
    Quick breakpoint - returns formatted address for PIE binary.

    Args:
        offset: Offset from base
        elf_obj: ELF object (optional, uses global if not provided)
        process_obj: Process object (optional, uses global if not provided)

    Returns:
        Actual address in memory

    Example:
        addr = bp(0x1234)
    """
    elf = elf_obj if elf_obj is not None else _elf
    p = process_obj if process_obj is not None else _process

    if elf is None:
        raise RuntimeError("ELF not set. Call setup(p, elf, libc) first.")
    if p is None:
        raise RuntimeError("Process not set. Call setup(p, elf, libc) first.")

    if elf.pie:
        base = p.libs().get(p.elf.path, 0)
        return base + offset
    return offset
