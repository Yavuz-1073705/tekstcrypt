"""Maakt ``python -m tekstcrypt`` mogelijk."""

import sys

from .cli import main

sys.exit(main())
