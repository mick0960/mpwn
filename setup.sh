#!/bin/bash

echo "Installing required dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip patchelf file zstd binutils

echo "Installing Python dependencies..."
pip3 install zstandard python-magic prettytable jinja2 requests beautifulsoup4

INSTALL_DIR="/usr/lib/mpwn"
echo "Creating installation directory: $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR/utils"

echo "Copying files..."
sudo cp mpwn.py "$INSTALL_DIR/"
sudo cp utils/* "$INSTALL_DIR/utils/"

echo "Creating executable in /usr/bin..."
sudo tee /usr/bin/mpwn > /dev/null << 'EOF'
#!/bin/bash
export PYTHONPATH=/usr/lib/mpwn

exec python3 /usr/lib/mpwn/mpwn.py "$@"
EOF

sudo chmod +x /usr/bin/mpwn
sudo chmod +x /usr/lib/mpwn/mpwn.py

USER_HOME=$(eval echo "~$SUDO_USER")
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
#----------------function area start----------------#
sla = lambda ch,data:p.sendlineafter(ch,data)
sda = lambda ch,data:p.sendafter(ch,data)
sd = lambda data:p.send(data)
sl = lambda data:p.sendline(data)
addr32 = lambda:u32(p.recvuntil(b"\xf7")[-4:])
addr64 = lambda:u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
ru = lambda con:p.recvuntil(con)

def lg(addr):
    frame = inspect.currentframe().f_back
    variables = {id(val): name for name, val in frame.f_locals.items()}
    addr_name = variables.get(id(addr), "Unknown")
    log.success(f"{addr_name} --> {hex(addr) if isinstance(addr, int) else addr}")

def debug(pie=0, bp=None):
    if pie:
        base = p.libs()[p.elf.path]
        if bp:
            if isinstance(bp, str):
                bp = f"*{hex(base + int(bp, 16))}"
            elif isinstance(bp, list):
                bp = [f"*{hex(base + int(b, 16))}" for b in bp]
        gdb.attach(p, gdbscript="\n".join(bp) if bp else None)
    else:
        if bp:
            if isinstance(bp, str):
                bp = f"b {bp}"
            elif isinstance(bp, list):
                bp = [f"b {b}" for b in bp]
        gdb.attach(p, gdbscript="\n".join(bp) if bp else None)
    pause()
#----------------function area end------------------#
#----------------predefine area start------------------#
elf_name = "{{filename}}"
p = process(elf_name)
context.log_level='debug'
elf = context.binary = ELF(elf_name)
libc_name = "{{libcname}}"
libc = ELF(libc_name) if libc_name else None
#----------------predefine area end------------------#

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

sudo chown -R "$SUDO_USER:$SUDO_USER" "$USER_CONFIG"

echo ""
echo "============================================================"
echo "MPWN has been successfully installed!"
echo ""
echo "Usage:"
echo "  mpwn [options] <executable> [libc_version]"
echo "Options:"
echo "  mpwn --fetch       # List available glibc versions"
echo "  mpwn --fetch-all   # Download all glibc libraries"
echo ""
echo "Your exploit templates are stored in: $USER_CONFIG"
echo "============================================================"
