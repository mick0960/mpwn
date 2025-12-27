#!/bin/bash

echo "Installing required dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip patchelf file zstd binutils

echo "Installing Python dependencies..."
pip3 install zstandard python-magic prettytable jinja2 requests beautifulsoup4

INSTALL_DIR="/usr/lib/mpwn"
echo "Creating installation directory: $INSTALL_DIR"
sudo rm -rf "$INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"

echo "Copying files..."
# Copy the new package structure
sudo cp -r mpwn "$INSTALL_DIR/"
sudo cp mpwn.py "$INSTALL_DIR/"

echo "Creating executable in /usr/bin..."
sudo tee /usr/bin/mpwn > /dev/null << 'EOF'
#!/bin/bash
export PYTHONPATH=/usr/lib/mpwn

exec python3 -m mpwn "$@"
EOF

sudo chmod +x /usr/bin/mpwn
sudo chmod +x /usr/lib/mpwn/mpwn.py

USER_HOME=$(eval echo "~$SUDO_USER")
if [ -z "$USER_HOME" ] || [ "$USER_HOME" = "~" ]; then
    USER_HOME="$HOME"
fi
USER_CONFIG="$USER_HOME/.config/mpwn"
echo "Creating user configuration directory: $USER_CONFIG"
mkdir -p "$USER_CONFIG"

if [ ! -f "$USER_CONFIG/template.py" ]; then
    echo "Creating default template..."
    cat > "$USER_CONFIG/template.py" << 'EOF'
#!/usr/bin/env python3
'''
    author: {{author}}
    time: {{time}}
'''
from pwn import *
from ctypes import *
import inspect

#================== Config ==================#
elf_name = "{{filename}}"
libc_name = "{{libcname}}"
host, port = "", 0

#================== Setup ==================#
context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF(elf_name)
libc = ELF(libc_name) if libc_name else None

def conn(argv=[], env={}):
    if args.REMOTE:
        return remote(host, port)
    return process([elf_name] + argv, env=env)

#================== Shortcuts ==================#
sla = lambda d, c: p.sendlineafter(d, c)
sda = lambda d, c: p.sendafter(d, c)
sl = lambda c: p.sendline(c)
sd = lambda c: p.send(c)
ru = lambda d, **kw: p.recvuntil(d, **kw)
rl = lambda: p.recvline()
rc = lambda n: p.recv(n)

#================== Address Leak ==================#
def leak64(prefix=b'\x7f', length=6):
    """Leak 64-bit address ending with prefix"""
    return u64(p.recvuntil(prefix)[-length:].ljust(8, b'\x00'))

def leak32(prefix=b'\xf7', length=4):
    """Leak 32-bit address ending with prefix"""
    return u32(p.recvuntil(prefix)[-length:])

def leak(name, addr):
    """Log leaked address with name"""
    log.success(f'{name}: {hex(addr)}')
    return addr

def lg(val):
    """Auto-detect variable name and log its value"""
    frame = inspect.currentframe().f_back
    names = {id(v): k for k, v in frame.f_locals.items()}
    name = names.get(id(val), 'value')
    if isinstance(val, int):
        log.success(f'{name} = {hex(val)}')
    else:
        log.success(f'{name} = {val}')

#================== Debug ==================#
def debug(bp=None, script='', pause_after=True):
    """
    Attach GDB with breakpoints.

    Args:
        bp: Breakpoint(s) - supports multiple formats:
            - int/hex: Address or offset (auto-detect PIE)
            - str: Symbol name, hex string "0x1234", or raw gdb command
            - list: Multiple breakpoints
            - dict: {'elf': [...], 'libc': [...]} for different bases
        script: Additional GDB commands to execute
        pause_after: Whether to pause after attach

    Examples:
        debug(0x1234)                    # Break at offset 0x1234 (PIE auto)
        debug("main")                    # Break at symbol
        debug([0x1234, "vuln", 0x5678])  # Multiple breakpoints
        debug({'elf': [0x1234], 'libc': [0x5678]})  # Different bases
        debug(0x1234, "set $a=1")        # With extra gdb commands
    """
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
                return f'b *{hex(base + b)}'
            return f'b *{hex(b)}'
        elif isinstance(b, str):
            # String: check if hex, symbol, or raw command
            b = b.strip()
            if b.startswith('0x') or b.startswith('0X'):
                addr = int(b, 16)
                if base or elf.pie:
                    return f'b *{hex(base + addr)}'
                return f'b *{hex(addr)}'
            elif b.startswith('b ') or b.startswith('break '):
                return b  # Raw gdb command
            else:
                return f'b {b}'  # Symbol name
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
        if 'elf' in bp:
            gdbscript_lines.extend(process_bps(bp['elf'], elf_base))
        if 'libc' in bp:
            gdbscript_lines.extend(process_bps(bp['libc'], libc_base))
        # Other keys treated as raw breakpoints
        for key in bp:
            if key not in ('elf', 'libc'):
                gdbscript_lines.extend(process_bps(bp[key]))
    else:
        gdbscript_lines.extend(process_bps(bp, elf_base))

    # Add custom script
    if script:
        gdbscript_lines.append(script)

    # Add continue command if breakpoints set
    if gdbscript_lines:
        gdbscript_lines.append('c')

    gdb.attach(p, gdbscript='\n'.join(gdbscript_lines))

    if pause_after:
        pause()

def bp(offset):
    """Quick breakpoint - returns formatted address for PIE binary"""
    if elf.pie:
        base = p.libs().get(p.elf.path, 0)
        return base + offset
    return offset

#================== Exploit ==================#
p = conn()
context.log_level = 'debug'

# Your exploit code here


p.interactive()
EOF
fi

if [ ! -f "$USER_CONFIG/config.json" ]; then
    echo "Creating default config..."
    cat > "$USER_CONFIG/config.json" << 'EOF'
{
    "script_name": "1.py",
    "author": "mick0960",
    "fields": "value"
}
EOF
fi

if [ -n "$SUDO_USER" ]; then
    sudo chown -R "$SUDO_USER:$SUDO_USER" "$USER_CONFIG"
fi

echo ""
echo "============================================================"
echo "MPwn v2.0 has been successfully installed!"
echo ""
echo "Usage:"
echo "  mpwn [options] <executable> [libc_version]"
echo ""
echo "Options:"
echo "  mpwn --fetch       # List available glibc versions"
echo "  mpwn --fetch-all   # Download all glibc libraries"
echo "  mpwn --version     # Show version information"
echo ""
echo "Your exploit template is stored in: $USER_CONFIG"
echo "============================================================"
