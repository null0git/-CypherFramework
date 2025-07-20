"""
Session Manager
Handles all active sessions (shells, connections, etc.)
"""

import asyncio
import uuid
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class Session:
    """Represents an active session with a target."""
    
    def __init__(self, session_id: str, session_type: str, target: str, **kwargs):
        self.id = session_id
        self.type = session_type
        self.target = target
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.active = True
        self.metadata = kwargs
        self.command_history = []
        
    async def execute(self, command: str) -> Dict:
        """Execute a command in this session."""
        self.last_activity = datetime.utcnow()
        self.command_history.append({
            'command': command,
            'timestamp': self.last_activity,
            'result': None
        })
        
        # Simulate command execution (replace with actual implementation)
        if self.type == "shell":
            result = await self._execute_shell_command(command)
        elif self.type == "meterpreter":
            result = await self._execute_meterpreter_command(command)
        else:
            result = {"output": "Unknown session type", "success": False}
            
        self.command_history[-1]['result'] = result
        return result
        
    async def _execute_shell_command(self, command: str) -> Dict:
        """Execute shell command (demo implementation)."""
        # This would connect to actual shell in real implementation
        demo_outputs = {
            "whoami": "nt authority\\system",
            "pwd": "/home/user",
            "ls": "file1.txt  file2.txt  directory1",
            "ps": "PID    PPID   NAME\n1234   1      explorer.exe\n5678   1234   notepad.exe"
        }
        
        output = demo_outputs.get(command.split()[0] if command.split() else "", 
                                 f"Executed: {command}")
        
        return {
            "output": output,
            "success": True,
            "exit_code": 0
        }
        
    async def _execute_meterpreter_command(self, command: str) -> Dict:
        """Execute Meterpreter command (demo implementation)."""
        meterpreter_commands = {
            "sysinfo": "Computer: TARGET-PC\nOS: Windows 10\nArchitecture: x64",
            "getuid": "Server username: NT AUTHORITY\\SYSTEM",
            "pwd": "C:\\Windows\\System32",
            "ps": "Process List\n============\nPID   Name\n----  ----\n1234  explorer.exe\n5678  notepad.exe"
        }
        
        output = meterpreter_commands.get(command.split()[0] if command.split() else "",
                                        f"meterpreter > {command}")
        
        return {
            "output": output,
            "success": True,
            "type": "meterpreter"
        }
        
    def to_dict(self) -> Dict:
        """Convert session to dictionary."""
        return {
            'id': self.id,
            'type': self.type,
            'target': self.target,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'active': self.active,
            'metadata': self.metadata,
            'command_count': len(self.command_history)
        }

class SessionManager:
    """Manages all active sessions."""
    
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.session_subscribers = []
        
    async def initialize(self):
        """Initialize the session manager."""
        logger.info("Session manager initialized")
        
        # Create demo sessions
        await self.create_session("shell", "192.168.1.105", os="windows")
        await self.create_session("meterpreter", "10.0.0.50", os="linux")
        await self.create_session("shell", "192.168.1.120", os="linux")
        
    async def create_session(self, session_type: str, target: str, **kwargs) -> str:
        """Create a new session."""
        session_id = str(uuid.uuid4())
        session = Session(session_id, session_type, target, **kwargs)
        
        self.sessions[session_id] = session
        
        logger.info(f"Created session {session_id} ({session_type}) to {target}")
        
        # Notify subscribers
        await self._notify_session_created(session)
        
        return session_id
        
    async def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        return self.sessions.get(session_id)
        
    async def list_sessions(self) -> List[Dict]:
        """List all active sessions."""
        return [session.to_dict() for session in self.sessions.values() if session.active]
        
    async def execute_command(self, session_id: str, command: str) -> Dict:
        """Execute a command on a session."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found", "success": False}
            
        if not session.active:
            return {"error": "Session is inactive", "success": False}
            
        result = await session.execute(command)
        
        # Notify subscribers
        await self._notify_command_executed(session, command, result)
        
        return result
        
    async def close_session(self, session_id: str):
        """Close a session."""
        if session_id in self.sessions:
            self.sessions[session_id].active = False
            logger.info(f"Closed session {session_id}")
            
            # Notify subscribers
            await self._notify_session_closed(self.sessions[session_id])
            
    async def close_all_sessions(self):
        """Close all active sessions."""
        for session in self.sessions.values():
            if session.active:
                session.active = False
                
        logger.info("Closed all sessions")
        
    def subscribe_to_events(self, callback):
        """Subscribe to session events."""
        self.session_subscribers.append(callback)
        
    async def _notify_session_created(self, session: Session):
        """Notify subscribers of new session."""
        for callback in self.session_subscribers:
            try:
                await callback("session_created", session.to_dict())
            except Exception as e:
                logger.error(f"Error notifying subscriber: {e}")
                
    async def _notify_command_executed(self, session: Session, command: str, result: Dict):
        """Notify subscribers of command execution."""
        event_data = {
            "session_id": session.id,
            "command": command,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        for callback in self.session_subscribers:
            try:
                await callback("command_executed", event_data)
            except Exception as e:
                logger.error(f"Error notifying subscriber: {e}")
                
    async def _notify_session_closed(self, session: Session):
        """Notify subscribers of session closure."""
        for callback in self.session_subscribers:
            try:
                await callback("session_closed", session.to_dict())
            except Exception as e:
                logger.error(f"Error notifying subscriber: {e}")