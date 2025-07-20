"""
Advanced Web Application Scanner
Comprehensive web vulnerability scanner with multiple detection techniques.
"""

import asyncio
import socket
import urllib.parse
import re
import ssl as ssl_module
from ..templates.base_auxiliary import BaseAuxiliary

class WebScanner(BaseAuxiliary):
    """Advanced web application vulnerability scanner."""
    
    name = "Advanced Web Scanner"
    description = "Comprehensive web application vulnerability scanner"
    author = "CypherFramework Team"
    version = "2.0"
    category = "scanner"
    
    def _default_options(self):
        return {
            'RHOSTS': {'value': '', 'required': True, 'description': 'Target host(s)'},
            'RPORT': {'value': 80, 'required': True, 'description': 'Target port'},
            'SSL': {'value': False, 'required': False, 'description': 'Use HTTPS'},
            'THREADS': {'value': 10, 'required': False, 'description': 'Number of threads'},
            'TIMEOUT': {'value': 10, 'required': False, 'description': 'Connection timeout'},
            'USER_AGENT': {'value': 'CypherFramework/2.0', 'required': False, 'description': 'User-Agent string'},
            'SCAN_PATHS': {'value': True, 'required': False, 'description': 'Scan common paths'},
            'SCAN_HEADERS': {'value': True, 'required': False, 'description': 'Analyze security headers'},
            'SCAN_VULNS': {'value': True, 'required': False, 'description': 'Check for vulnerabilities'},
        }
        
    def _required_options(self):
        return ['RHOSTS', 'RPORT']
        
    async def run(self, options):
        """Execute comprehensive web scan."""
        rhosts = self.get_option('RHOSTS')
        rport = self.get_option('RPORT')
        ssl = self.get_option('SSL')
        threads = self.get_option('THREADS')
        timeout = self.get_option('TIMEOUT')
        user_agent = self.get_option('USER_AGENT')
        scan_paths = self.get_option('SCAN_PATHS')
        scan_headers = self.get_option('SCAN_HEADERS')
        scan_vulns = self.get_option('SCAN_VULNS')
        
        # Parse hosts
        hosts = self._parse_hosts(rhosts)
        
        # Create scan tasks
        tasks = []
        semaphore = asyncio.Semaphore(threads)
        
        for host in hosts:
            task = self._scan_host(semaphore, host, rport, ssl, timeout, user_agent, 
                                 scan_paths, scan_headers, scan_vulns)
            tasks.append(task)
            
        # Execute scans
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        scan_results = {}
        for result in results:
            if isinstance(result, dict) and 'host' in result:
                scan_results[result['host']] = result
                
        return {
            'success': True,
            'scan_results': scan_results,
            'total_hosts': len(hosts),
            'scanned': len([r for r in results if isinstance(r, dict)])
        }
        
    async def _scan_host(self, semaphore, host, port, ssl, timeout, user_agent, 
                        scan_paths, scan_headers, scan_vulns):
        """Scan a single host comprehensively."""
        async with semaphore:
            result = {
                'host': host,
                'port': port,
                'ssl': ssl,
                'accessible': False,
                'server_info': {},
                'security_headers': {},
                'common_paths': {},
                'vulnerabilities': [],
                'technologies': []
            }
            
            try:
                # Basic connectivity test
                base_response = await self._send_http_request(
                    host, port, '/', 'GET', {}, ssl, timeout, user_agent
                )
                
                if base_response:
                    result['accessible'] = True
                    
                    # Extract server information
                    result['server_info'] = self._extract_server_info(base_response)
                    
                    # Detect technologies
                    result['technologies'] = self._detect_technologies(base_response)
                    
                    # Scan security headers
                    if scan_headers:
                        result['security_headers'] = self._analyze_security_headers(base_response)
                        
                    # Scan common paths
                    if scan_paths:
                        result['common_paths'] = await self._scan_common_paths(
                            host, port, ssl, timeout, user_agent
                        )
                        
                    # Vulnerability scanning
                    if scan_vulns:
                        result['vulnerabilities'] = await self._scan_vulnerabilities(
                            host, port, ssl, timeout, user_agent, base_response
                        )
                        
            except Exception as e:
                result['error'] = str(e)
                
            return result
            
    async def _send_http_request(self, host, port, path, method='GET', headers=None, 
                               ssl=False, timeout=10, user_agent='CypherFramework/2.0', data=None):
        """Send HTTP request and return response."""
        if headers is None:
            headers = {}
            
        # Default headers
        default_headers = {
            'User-Agent': user_agent,
            'Accept': '*/*',
            'Connection': 'close'
        }
        default_headers.update(headers)
        
        # Build request
        request_line = f"{method} {path} HTTP/1.1\r\n"
        request_line += f"Host: {host}:{port}\r\n"
        
        for header, value in default_headers.items():
            request_line += f"{header}: {value}\r\n"
            
        if data:
            request_line += f"Content-Length: {len(data)}\r\n"
            
        request_line += "\r\n"
        
        if data:
            request_line += data
            
        try:
            # Connect
            if ssl:
                context = ssl_module.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl_module.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock = context.wrap_socket(sock, server_hostname=host)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
            sock.connect((host, port))
            sock.send(request_line.encode())
            
            # Receive response
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if b"\r\n\r\n" in response:
                        # Got headers, continue reading body
                        continue
                except socket.timeout:
                    break
                    
            sock.close()
            return response.decode('utf-8', errors='ignore')
            
        except Exception:
            return None
            
    def _extract_server_info(self, response):
        """Extract server information from HTTP response."""
        info = {}
        
        lines = response.split('\r\n')
        
        # Status line
        if lines:
            status_line = lines[0]
            if 'HTTP/' in status_line:
                parts = status_line.split(' ', 2)
                if len(parts) >= 2:
                    info['status_code'] = parts[1]
                if len(parts) >= 3:
                    info['status_message'] = parts[2]
                    
        # Headers
        for line in lines[1:]:
            if ':' in line:
                header, value = line.split(':', 1)
                header = header.strip().lower()
                value = value.strip()
                
                if header == 'server':
                    info['server'] = value
                elif header == 'x-powered-by':
                    info['powered_by'] = value
                elif header == 'content-type':
                    info['content_type'] = value
                elif header == 'content-length':
                    info['content_length'] = value
                    
        return info
        
    def _detect_technologies(self, response):
        """Detect web technologies from response."""
        technologies = []
        
        response_lower = response.lower()
        
        # Server detection
        if 'apache' in response_lower:
            technologies.append('Apache')
        if 'nginx' in response_lower:
            technologies.append('Nginx')
        if 'iis' in response_lower:
            technologies.append('IIS')
            
        # Framework detection
        if 'php' in response_lower:
            technologies.append('PHP')
        if 'asp.net' in response_lower or 'aspnet' in response_lower:
            technologies.append('ASP.NET')
        if 'jsp' in response_lower or 'java' in response_lower:
            technologies.append('Java')
        if 'python' in response_lower or 'django' in response_lower:
            technologies.append('Python')
        if 'ruby' in response_lower or 'rails' in response_lower:
            technologies.append('Ruby')
        if 'node.js' in response_lower or 'express' in response_lower:
            technologies.append('Node.js')
            
        # CMS detection
        if 'wordpress' in response_lower or 'wp-' in response_lower:
            technologies.append('WordPress')
        if 'drupal' in response_lower:
            technologies.append('Drupal')
        if 'joomla' in response_lower:
            technologies.append('Joomla')
            
        # JavaScript frameworks
        if 'react' in response_lower:
            technologies.append('React')
        if 'angular' in response_lower:
            technologies.append('Angular')
        if 'vue' in response_lower:
            technologies.append('Vue.js')
            
        return list(set(technologies))
        
    def _analyze_security_headers(self, response):
        """Analyze security headers in HTTP response."""
        security_headers = {
            'strict-transport-security': {'present': False, 'value': ''},
            'content-security-policy': {'present': False, 'value': ''},
            'x-frame-options': {'present': False, 'value': ''},
            'x-content-type-options': {'present': False, 'value': ''},
            'x-xss-protection': {'present': False, 'value': ''},
            'referrer-policy': {'present': False, 'value': ''},
            'permissions-policy': {'present': False, 'value': ''},
        }
        
        lines = response.split('\r\n')
        
        for line in lines:
            if ':' in line:
                header, value = line.split(':', 1)
                header = header.strip().lower()
                value = value.strip()
                
                if header in security_headers:
                    security_headers[header]['present'] = True
                    security_headers[header]['value'] = value
                    
        return security_headers
        
    async def _scan_common_paths(self, host, port, ssl, timeout, user_agent):
        """Scan for common web paths and files."""
        common_paths = [
            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/web.config',
            '/backup', '/config', '/test', '/dev', '/api', '/swagger',
            '/debug', '/info.php', '/phpinfo.php', '/server-info',
            '/status', '/health', '/metrics', '/actuator'
        ]
        
        results = {}
        
        # Limit concurrent requests
        semaphore = asyncio.Semaphore(5)
        
        async def check_path(path):
            async with semaphore:
                response = await self._send_http_request(
                    host, port, path, 'GET', {}, ssl, timeout, user_agent
                )
                
                if response:
                    status_code = self._extract_status_code(response)
                    if status_code and status_code != '404':
                        return {
                            'path': path,
                            'status_code': status_code,
                            'accessible': True,
                            'size': len(response)
                        }
                        
                return {'path': path, 'accessible': False}
                
        # Check all paths
        tasks = [check_path(path) for path in common_paths]
        path_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in path_results:
            if isinstance(result, dict):
                results[result['path']] = result
                
        return results
        
    async def _scan_vulnerabilities(self, host, port, ssl, timeout, user_agent, base_response):
        """Scan for common web vulnerabilities."""
        vulnerabilities = []
        
        # SQL Injection test
        sql_vuln = await self._test_sql_injection(host, port, ssl, timeout, user_agent)
        if sql_vuln:
            vulnerabilities.append(sql_vuln)
            
        # XSS test
        xss_vuln = await self._test_xss(host, port, ssl, timeout, user_agent)
        if xss_vuln:
            vulnerabilities.append(xss_vuln)
            
        # Directory traversal test
        lfi_vuln = await self._test_directory_traversal(host, port, ssl, timeout, user_agent)
        if lfi_vuln:
            vulnerabilities.append(lfi_vuln)
            
        # Command injection test
        cmd_vuln = await self._test_command_injection(host, port, ssl, timeout, user_agent)
        if cmd_vuln:
            vulnerabilities.append(cmd_vuln)
            
        return vulnerabilities
        
    async def _test_sql_injection(self, host, port, ssl, timeout, user_agent):
        """Test for SQL injection vulnerabilities."""
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        test_params = ['id', 'user', 'search', 'q', 'name']
        
        for param in test_params:
            for payload in payloads:
                test_url = f"/?{param}={urllib.parse.quote(payload)}"
                
                response = await self._send_http_request(
                    host, port, test_url, 'GET', {}, ssl, timeout, user_agent
                )
                
                if response and self._check_sql_error(response):
                    return {
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'parameter': param,
                        'payload': payload,
                        'description': 'Potential SQL injection vulnerability detected'
                    }
                    
        return None
        
    async def _test_xss(self, host, port, ssl, timeout, user_agent):
        """Test for Cross-Site Scripting vulnerabilities."""
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        
        test_params = ['search', 'q', 'name', 'comment', 'message']
        
        for param in test_params:
            for payload in payloads:
                test_url = f"/?{param}={urllib.parse.quote(payload)}"
                
                response = await self._send_http_request(
                    host, port, test_url, 'GET', {}, ssl, timeout, user_agent
                )
                
                if response and payload in response:
                    return {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'Medium',
                        'parameter': param,
                        'payload': payload,
                        'description': 'Potential XSS vulnerability detected'
                    }
                    
        return None
        
    async def _test_directory_traversal(self, host, port, ssl, timeout, user_agent):
        """Test for directory traversal vulnerabilities."""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        test_params = ['file', 'path', 'page', 'include', 'template']
        
        for param in test_params:
            for payload in payloads:
                test_url = f"/?{param}={urllib.parse.quote(payload)}"
                
                response = await self._send_http_request(
                    host, port, test_url, 'GET', {}, ssl, timeout, user_agent
                )
                
                if response and self._check_file_inclusion(response):
                    return {
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'parameter': param,
                        'payload': payload,
                        'description': 'Potential directory traversal vulnerability detected'
                    }
                    
        return None
        
    async def _test_command_injection(self, host, port, ssl, timeout, user_agent):
        """Test for command injection vulnerabilities."""
        payloads = [
            "; ls",
            "| whoami",
            "&& id",
            "`uname -a`",
            "$(whoami)"
        ]
        
        test_params = ['cmd', 'command', 'exec', 'system', 'ping']
        
        for param in test_params:
            for payload in payloads:
                test_url = f"/?{param}={urllib.parse.quote(payload)}"
                
                response = await self._send_http_request(
                    host, port, test_url, 'GET', {}, ssl, timeout, user_agent
                )
                
                if response and self._check_command_execution(response):
                    return {
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'parameter': param,
                        'payload': payload,
                        'description': 'Potential command injection vulnerability detected'
                    }
                    
        return None
        
    def _check_sql_error(self, response):
        """Check for SQL error patterns in response."""
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'ora-', 'microsoft ole db',
            'odbc', 'sqlite_', 'postgresql', 'warning: mysql',
            'valid mysql result', 'mysqlclient', 'microsoft jet database'
        ]
        
        response_lower = response.lower()
        return any(error in response_lower for error in sql_errors)
        
    def _check_file_inclusion(self, response):
        """Check for file inclusion indicators in response."""
        file_indicators = [
            'root:x:', '/bin/bash', '/bin/sh', 'daemon:x:',
            '[boot loader]', '[operating systems]', 'localhost',
            '127.0.0.1'
        ]
        
        return any(indicator in response for indicator in file_indicators)
        
    def _check_command_execution(self, response):
        """Check for command execution indicators in response."""
        command_indicators = [
            'uid=', 'gid=', 'groups=', 'linux', 'windows nt',
            'microsoft windows', 'total ', 'drwx', '-rw-'
        ]
        
        response_lower = response.lower()
        return any(indicator in response_lower for indicator in command_indicators)
        
    def _extract_status_code(self, response):
        """Extract HTTP status code from response."""
        lines = response.split('\r\n')
        if lines:
            status_line = lines[0]
            if 'HTTP/' in status_line:
                parts = status_line.split(' ')
                if len(parts) >= 2:
                    return parts[1]
        return None
        
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