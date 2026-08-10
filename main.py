#!/usr/bin/env python3
"""REDEYE entry point.

REDEYE now runs on Godot. This script starts the **backend daemon**; the UI is
the Godot project in ``godot/`` (open it in Godot 4.2+ and press F5). The old
pygame console has been removed, so there is no pygame dependency anymore.

    python main.py                 # start the backend (same as: python serve.py)
    python main.py --host 0.0.0.0  # let other machines on the LAN connect

See godot/README.md for the full run instructions and wire protocol.
"""
from serve import main

if __name__ == "__main__":
    raise SystemExit(main())
