#!/usr/bin/env python
import sys

try:
    import server
    print("✓ Syntax OK - server.py imports successfully")
except SyntaxError as e:
    print(f"✗ Syntax Error: {e}")
    sys.exit(1)
except ImportError as e:
    print(f"⚠ Import Error (dependencies): {e}")
    print("Note: Syntax is OK, but missing dependencies")
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
