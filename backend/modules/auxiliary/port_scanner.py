"""
Port Scanner Auxiliary Module
Scans for open ports on target hosts.
"""

import asyncio
import socket
from ..templates.base_auxiliary import BaseAuxiliary

class PortScanner(BaseAuxiliary):
    """TCP Port Scanner auxiliary module."""
    
    name = "TCP Port Scanner"
    description = "Scan for open TCP ports on target hosts"
    author = "CypherFramework Team"
    version = "1.0"
    category = "scanner"
    
    def _default_options(self):
        return {
            'RHOSTS': {'value': '', 'required': True, 'description': 'Target host(s)'},
            'PORTS': {'value': '22,80,443,445,3389', 'required': True, 'description': 'Ports to scan'},
            'THREADS': {'value': 100, 'required': False, 'description': 'Number of threads'},
            'TIMEOUT': {'value': 3, 'required': False, 'description': 'Connection timeout'},
        }
        
    def _required_options(self):
        return ['RHOSTS', 'PORTS']
        
    async def run(self, options):
        """Execute port scan."""
        rhosts = self.get_option('RHOSTS')
        ports = self.get_option('PORTS')
        threads = self.get_option('THREADS')
        timeout = self.get_option('TIMEOUT')
        
        # Parse hosts and ports
        hosts = self._parse_hosts(rhosts)
        port_list = self._parse_ports(ports)
        
        # Create scan tasks
        tasks = []
        semaphore = asyncio.Semaphore(threads)
        
        for host in hosts:
            for port in port_list:
                task = self._scan_port(semaphore, host, port, timeout)
                tasks.append(task)
                
        # Execute scans
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        open_ports = {}
        for result in results:
            if isinstance(result, dict) and result.get('open'):
                host = result['host']
                if host not in open_ports:
                    open_ports[host] = []
                open_ports[host].append({
                    'port': result['port'],
                    'service': self._guess_service(result['port']),
                    'banner': result.get('banner', '')
                })
                
        return {
            'success': True,
            'open_ports': open_ports,
            'total_hosts': len(hosts),
            'total_ports': len(port_list),
            'scanned': len(tasks)
        }
        
    async def _scan_port(self, semaphore, host, port, timeout):
        """Scan a single port."""
        async with semaphore:
            try:
                # Create connection
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=timeout)
                
                # Try to grab banner
                banner = ""
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(1024), timeout=1)
                    banner = data.decode(errors='ignore').strip()
                except:
                    pass
                    
                writer.close()
                await writer.wait_closed()
                
                return {
                    'host': host,
                    'port': port,
                    'open': True,
                    'banner': banner
                }
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return {
                    'host': host,
                    'port': port,
                    'open': False
                }
                
    def _parse_hosts(self, rhosts):
        """Parse host specification."""
        hosts = []
        
        for host_spec in rhosts.split(','):
            host_spec = host_spec.strip()
            
            if '-' in host_spec and '.' in host_spec:
                # IP range like 192.168.1.1-10
                base_ip, end_range = host_spec.rsplit('.', 1)
                if '-' in end_range:
                    start, end = end_range.split('-')
                    for i in range(int(start), int(end) + 1):
                        hosts.append(f"{base_ip}.{i}")
                else:
                    hosts.append(host_spec)
            else:
                hosts.append(host_spec)
                
        return hosts
        
    def _parse_ports(self, ports):
        """Parse port specification."""
        port_list = []
        
        for port_spec in ports.split(','):
            port_spec = port_spec.strip()
            
            if '-' in port_spec:
                start, end = port_spec.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(port_spec))
                
        return sorted(set(port_list))
        
    def _guess_service(self, port):
        """Guess service based on port number."""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
            3389: 'rdp', 5432: 'postgresql', 3306: 'mysql',
            1433: 'mssql', 6379: 'redis', 27017: 'mongodb'
        }
        
        return common_ports.get(port, 'unknown')