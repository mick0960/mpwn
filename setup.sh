#!/bin/bash

echo "Installing required dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip patchelf file zstd binutils

echo "Installing Python dependencies..."
pip3 install zstandard python-magic prettytable jinja2 requests beautifulsoup4 pwntools

echo "Installing mpwn package..."
pip3 install /home/mick0960/mpwn --force-reinstall --no-deps

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

echo "Creating default template..."
cat > "$USER_CONFIG/template.py" << 'EOF'
#!/usr/bin/env python3
'''
    author: {{author}}
    time: {{time}}
'''
from mpwn import *

#================== Config ==================#
elf_name = "{{filename}}"
libc_name = "{{libcname}}"
host, port = "", 0

#================== Setup ==================#
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

elf = context.binary = ELF(elf_name)
libc = ELF(libc_name) if libc_name else None

#================== Connection ==================#
p = conn(elf_name, host, port)
setup(p, elf, libc)


p.interactive()
EOF

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
