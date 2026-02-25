"""
conftest.py — pytest root configuration for status-tracker project.

This file MUST exist at the project root (alongside main.py, not inside tests/).
It adds the project root directory to sys.path so that test modules can use
absolute imports like `from main import app` without any relative path gymnastics.

pytest discovers this file automatically before any test collection begins.
Location requirement: project root directory, not tests/ subdirectory.
"""

import sys
import os

# Insert the project root at the front of sys.path.
# os.path.dirname(__file__) resolves to the directory containing this file,
# which is the project root when conftest.py is placed correctly.
sys.path.insert(0, os.path.dirname(__file__))
