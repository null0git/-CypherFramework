#!/usr/bin/env python3
"""
CypherFramework - Quick Start Script
For development and testing purposes only.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add backend to Python path
sys.path.insert(0, str(Path(__file__).parent))

from main import main

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════╗
    ║          CypherFramework v1.0.0           ║
    ║     Professional Penetration Testing     ║
    ║             Framework                     ║
    ╚═══════════════════════════════════════════╝
    
    WARNING: This tool is for authorized testing only.
    Unauthorized use is illegal and unethical.
    
    Starting framework...
    """)
    
    # Set default to web mode for development
    if len(sys.argv) == 1:
        sys.argv.extend(['--mode', 'web', '--host', '127.0.0.1', '--port', '8000'])
    
    asyncio.run(main())