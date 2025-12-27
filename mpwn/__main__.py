"""
MPwn package entry point.

Allows running the package as a module: python -m mpwn
"""

import sys
from mpwn.cli import main

if __name__ == "__main__":
    sys.exit(main())
