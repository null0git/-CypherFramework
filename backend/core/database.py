"""
Database Manager
Handles CVE database, targets, sessions, and logging.
"""

import aiosqlite
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages all database operations."""
    
    def __init__(self):
        self.db_path = None
        self.connection = None
        
    async def initialize(self, config: Dict):
        """Initialize database connection and schema."""
        self.db_path = config.get('path', 'database/cypher.db')
        
        # Ensure directory exists
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Create tables
        await self._create_schema()
        
        # Populate with demo data
        await self._populate_demo_data()
        
        logger.info(f"Database initialized: {self.db_path}")
        
    async def _create_schema(self):
        """Create database schema."""
        async with aiosqlite.connect(self.db_path) as db:
            # CVE database
            await db.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    score REAL,
                    published_date TEXT,
                    modified_date TEXT,
                    references TEXT,
                    cpe_matches TEXT
                )
            ''')
            
            # Targets
            await db.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    hostname TEXT,
                    os_type TEXT,
                    os_version TEXT,
                    services TEXT,
                    status TEXT,
                    discovered_at TEXT,
                    last_scanned TEXT
                )
            ''')
            
            # Vulnerabilities
            await db.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    cve_id TEXT,
                    service TEXT,
                    port INTEGER,
                    status TEXT,
                    confidence REAL,
                    discovered_at TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets (id),
                    FOREIGN KEY (cve_id) REFERENCES cves (id)
                )
            ''')
            
            # Sessions
            await db.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    session_type TEXT,
                    target_id INTEGER,
                    status TEXT,
                    created_at TEXT,
                    closed_at TEXT,
                    metadata TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets (id)
                )
            ''')
            
            # Module executions
            await db.execute('''
                CREATE TABLE IF NOT EXISTS module_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_name TEXT,
                    options TEXT,
                    result TEXT,
                    executed_at TEXT,
                    success BOOLEAN
                )
            ''')
            
            # Activity log
            await db.execute('''
                CREATE TABLE IF NOT EXISTS activity_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    level TEXT,
                    module TEXT,
                    action TEXT,
                    details TEXT
                )
            ''')
            
            await db.commit()
            
    async def _populate_demo_data(self):
        """Populate database with demo data."""
        async with aiosqlite.connect(self.db_path) as db:
            # Check if data already exists
            cursor = await db.execute("SELECT COUNT(*) FROM cves")
            count = (await cursor.fetchone())[0]
            
            if count > 0:
                return  # Data already exists
                
            # Demo CVEs
            demo_cves = [
                ('CVE-2023-23397', 'Microsoft Outlook Privilege Escalation', 'Critical', 9.8),
                ('CVE-2022-26134', 'Atlassian Confluence RCE', 'Critical', 9.8),
                ('CVE-2021-44228', 'Apache Log4j RCE (Log4Shell)', 'Critical', 10.0),
                ('CVE-2023-21608', 'Adobe Acrobat Reader RCE', 'High', 7.8),
                ('CVE-2023-28252', 'Windows Common Log File System Driver', 'High', 7.8),
            ]
            
            for cve_id, desc, severity, score in demo_cves:
                await db.execute(
                    "INSERT OR IGNORE INTO cves (id, description, severity, score, published_date) VALUES (?, ?, ?, ?, ?)",
                    (cve_id, desc, severity, score, datetime.utcnow().isoformat())
                )
                
            # Demo targets
            demo_targets = [
                ('192.168.1.105', 'WIN-DESKTOP01', 'Windows', '10 Pro', '[{"port": 445, "service": "smb"}, {"port": 3389, "service": "rdp"}]'),
                ('10.0.0.50', 'web-server', 'Linux', 'Ubuntu 20.04', '[{"port": 80, "service": "http"}, {"port": 443, "service": "https"}, {"port": 22, "service": "ssh"}]'),
                ('192.168.1.120', 'db-server', 'Linux', 'CentOS 7', '[{"port": 3306, "service": "mysql"}, {"port": 22, "service": "ssh"}]'),
                ('10.0.0.75', 'mail-server', 'Windows', 'Server 2019', '[{"port": 25, "service": "smtp"}, {"port": 143, "service": "imap"}]'),
            ]
            
            for ip, hostname, os_type, os_version, services in demo_targets:
                await db.execute(
                    "INSERT OR IGNORE INTO targets (ip_address, hostname, os_type, os_version, services, status, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ip, hostname, os_type, os_version, services, 'active', datetime.utcnow().isoformat())
                )
                
            # Demo vulnerabilities
            demo_vulns = [
                (1, 'CVE-2023-23397', 'outlook', 443, 'exploitable', 0.95),
                (2, 'CVE-2022-26134', 'confluence', 8090, 'exploited', 0.98),
                (2, 'CVE-2021-44228', 'log4j', 8080, 'patched', 0.90),
                (3, 'CVE-2023-21608', 'mysql', 3306, 'exploitable', 0.85),
            ]
            
            for target_id, cve_id, service, port, status, confidence in demo_vulns:
                await db.execute(
                    "INSERT OR IGNORE INTO vulnerabilities (target_id, cve_id, service, port, status, confidence, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (target_id, cve_id, service, port, status, confidence, datetime.utcnow().isoformat())
                )
                
            await db.commit()
            
    async def get_targets(self) -> List[Dict]:
        """Get all targets."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM targets WHERE status = 'active'")
            rows = await cursor.fetchall()
            
            targets = []
            for row in rows:
                target = dict(row)
                target['services'] = json.loads(target['services']) if target['services'] else []
                targets.append(target)
                
            return targets
            
    async def get_vulnerabilities(self) -> List[Dict]:
        """Get all vulnerabilities with target info."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute('''
                SELECT v.*, t.ip_address, t.hostname, c.description, c.severity, c.score
                FROM vulnerabilities v
                JOIN targets t ON v.target_id = t.id
                JOIN cves c ON v.cve_id = c.id
                ORDER BY c.score DESC
            ''')
            return [dict(row) for row in await cursor.fetchall()]
            
    async def log_module_execution(self, module_name: str, options: Dict, result: Dict, timestamp: datetime):
        """Log module execution."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO module_executions (module_name, options, result, executed_at, success) VALUES (?, ?, ?, ?, ?)",
                (module_name, json.dumps(options), json.dumps(result), timestamp.isoformat(), result.get('success', False))
            )
            await db.commit()
            
    async def log_activity(self, level: str, module: str, action: str, details: str):
        """Log framework activity."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO activity_log (timestamp, level, module, action, details) VALUES (?, ?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), level, module, action, details)
            )
            await db.commit()
            
    async def close(self):
        """Close database connection."""
        if self.connection:
            await self.connection.close()