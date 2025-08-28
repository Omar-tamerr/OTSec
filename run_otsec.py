#!/usr/bin/env python3

import sys
import os

# Add src to the path
sys.path.insert(0, os.path.abspath("src"))

from otsec.cli import main

if __name__ == "__main__":
    main()

