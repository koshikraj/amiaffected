#!/usr/bin/env python3
"""Run amiaffected from this bundle and nothing else.

    python3 -I /abs/path/to/scripts/run.py check [--scan-root DIR ...]

-I (isolated mode) keeps the current directory, PYTHONPATH and the user
site directory off sys.path, so the only non-stdlib code that can load is
the copy that sits beside this file.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

if not sys.flags.isolated:
    sys.stderr.write("run.py: not started with python3 -I; modules in the current directory "
                     "or PYTHONPATH could shadow the tool. Re-run with -I.\n")
sys.dont_write_bytecode = True   # no writes, not even .pyc into the bundle
sys.path.insert(0, HERE)

from amiaffected.__main__ import main  # noqa: E402

sys.exit(main())
