"""
Core Framework Engine
Manages modules, sessions, and orchestrates all framework operations.
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import importlib.util
from datetime import datetime

from .module_loader import ModuleLoader
from .session_manager import SessionManager
from .database import DatabaseManager
from .payload_builder import PayloadBuilder
from .exploit_matcher import ExploitMatcher

logger = logging.getLogger(__name__)

class CypherFramework:
    """Main framework class that coordinates all components."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = {}
        self.module_loader = ModuleLoader()
        self.session_manager = SessionManager()
        self.db_manager = DatabaseManager()
        self.payload_builder = PayloadBuilder()
        self.exploit_matcher = ExploitMatcher()
        self.modules = {}
        self.active_sessions = {}
        self.running = False
        
    async def initialize(self):
        """Initialize all framework components."""
        logger.info("Initializing CypherFramework...")
        
        # Load configuration
        await self._load_config()
        
        # Initialize database
        await self.db_manager.initialize(self.config.get('database', {}))
        
        # Load all modules
        await self._load_modules()
        
        # Initialize session manager
        await self.session_manager.initialize()
        
        # Initialize exploit matcher
        await self.exploit_matcher.initialize(self.db_manager)
        
        self.running = True
        logger.info("CypherFramework initialized successfully")
        
    async def _load_config(self):
        """Load framework configuration."""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {self.config_path} not found, using defaults")
            self.config = self._default_config()
            
    def _default_config(self) -> Dict:
        """Return default configuration."""
        return {
            'framework': {'name': 'CypherFramework', 'version': '1.0.0'},
            'database': {'type': 'sqlite', 'path': 'database/cypher.db'},
            'modules': {'auto_load': True, 'paths': ['modules']},
            'logging': {'level': 'INFO'},
            'web': {'host': '127.0.0.1', 'port': 8000},
            'security': {'max_sessions': 10}
        }
        
    async def _load_modules(self):
        """Load all framework modules."""
        if not self.config.get('modules', {}).get('auto_load', True):
            return
            
        module_paths = self.config.get('modules', {}).get('paths', ['modules'])
        
        for path in module_paths:
            path_obj = Path(path)
            if path_obj.exists():
                await self.module_loader.load_from_directory(path_obj)
                
        self.modules = self.module_loader.get_all_modules()
        logger.info(f"Loaded {len(self.modules)} modules")
        
    async def get_modules_by_type(self, module_type: str) -> List[Dict]:
        """Get modules filtered by type."""
        return [m for m in self.modules.values() if m.get('type') == module_type]
        
    async def run_module(self, module_name: str, options: Dict) -> Dict:
        """Execute a module with given options."""
        if module_name not in self.modules:
            return {'success': False, 'error': f'Module {module_name} not found'}
            
        module = self.modules[module_name]
        
        try:
            # Validate options
            result = await module['instance'].run(options)
            
            # Log execution
            await self.db_manager.log_module_execution(
                module_name, options, result, datetime.utcnow()
            )
            
            return {'success': True, 'result': result}
            
        except Exception as e:
            logger.error(f"Error running module {module_name}: {e}")
            return {'success': False, 'error': str(e)}
            
    async def build_payload(self, os: str, arch: str, payload_type: str, 
                          lhost: str, lport: int, encoder: Optional[str] = None) -> bytes:
        """Build a payload with specified parameters."""
        return await self.payload_builder.build(
            os=os, arch=arch, payload_type=payload_type,
            lhost=lhost, lport=lport, encoder=encoder
        )
        
    async def match_exploits(self, target_info: Dict) -> List[Dict]:
        """Find matching exploits for a target."""
        return await self.exploit_matcher.find_matches(target_info)
        
    async def create_session(self, session_type: str, target: str, **kwargs) -> str:
        """Create a new session."""
        return await self.session_manager.create_session(
            session_type, target, **kwargs
        )
        
    async def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID."""
        return await self.session_manager.get_session(session_id)
        
    async def list_sessions(self) -> List[Dict]:
        """List all active sessions."""
        return await self.session_manager.list_sessions()
        
    async def execute_on_session(self, session_id: str, command: str) -> Dict:
        """Execute command on a session."""
        return await self.session_manager.execute_command(session_id, command)
        
    async def get_targets(self) -> List[Dict]:
        """Get all discovered targets."""
        return await self.db_manager.get_targets()
        
    async def get_vulnerabilities(self) -> List[Dict]:
        """Get discovered vulnerabilities."""
        return await self.db_manager.get_vulnerabilities()
        
    async def get_statistics(self) -> Dict:
        """Get framework statistics."""
        return {
            'modules_loaded': len(self.modules),
            'active_sessions': len(await self.list_sessions()),
            'targets_discovered': len(await self.get_targets()),
            'vulnerabilities_found': len(await self.get_vulnerabilities()),
            'uptime': (datetime.utcnow() - self.start_time).total_seconds() if hasattr(self, 'start_time') else 0
        }
        
    async def shutdown(self):
        """Gracefully shutdown the framework."""
        logger.info("Shutting down CypherFramework...")
        
        # Close all sessions
        await self.session_manager.close_all_sessions()
        
        # Close database connections
        await self.db_manager.close()
        
        self.running = False
        logger.info("CypherFramework shutdown complete")