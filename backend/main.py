#!/usr/bin/env python3
"""
CypherFramework - Advanced Ethical Hacking Framework
Created for authorized penetration testing with explicit permission.

WARNING: This tool is for educational and authorized testing purposes only.
Unauthorized use is illegal and unethical.
"""

import asyncio
import argparse
import sys
from pathlib import Path

# Add backend to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.framework import CypherFramework
from cli.console import CypherConsole
from web.server import WebServer

async def main():
    parser = argparse.ArgumentParser(description='CypherFramework - Ethical Hacking Platform')
    parser.add_argument('--mode', choices=['cli', 'web', 'build'], default='web',
                       help='Framework operation mode')
    parser.add_argument('--host', default='127.0.0.1', help='Web server host')
    parser.add_argument('--port', type=int, default=8000, help='Web server port')
    
    # Payload builder arguments
    parser.add_argument('--os', choices=['windows', 'linux', 'macos', 'android'], 
                       help='Target operating system')
    parser.add_argument('--arch', choices=['x86', 'x64', 'arm', 'arm64'], 
                       help='Target architecture')
    parser.add_argument('--type', choices=['reverse_tcp', 'bind_tcp', 'reverse_http', 'reverse_https'],
                       help='Payload type')
    parser.add_argument('--lhost', help='Local host for reverse connections')
    parser.add_argument('--lport', type=int, help='Local port for connections')
    parser.add_argument('--output', help='Output file for generated payload')
    
    args = parser.parse_args()
    
    # Initialize framework
    framework = CypherFramework()
    await framework.initialize()
    
    if args.mode == 'cli':
        console = CypherConsole(framework)
        await console.start()
    elif args.mode == 'web':
        server = WebServer(framework, args.host, args.port)
        await server.start()
    elif args.mode == 'build':
        if not all([args.os, args.arch, args.type, args.lhost, args.lport]):
            print("Error: All payload parameters required for build mode")
            sys.exit(1)
        payload = await framework.build_payload(
            os=args.os, arch=args.arch, payload_type=args.type,
            lhost=args.lhost, lport=args.lport
        )
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(payload)
            print(f"Payload saved to {args.output}")
        else:
            print("Generated payload (hex):")
            print(payload.hex())

if __name__ == "__main__":
    asyncio.run(main())