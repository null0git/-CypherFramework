"""
FastAPI Web Server
Provides REST API and WebSocket endpoints for the web interface.
"""

import asyncio
import json
import logging
from typing import Dict, Any, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

logger = logging.getLogger(__name__)

# Request/Response Models
class ModuleExecuteRequest(BaseModel):
    module_name: str
    options: Dict[str, Any]

class PayloadBuildRequest(BaseModel):
    os: str
    arch: str
    payload_type: str
    lhost: str
    lport: int
    encoder: str = None

class SessionCommandRequest(BaseModel):
    session_id: str
    command: str

class WebServer:
    """FastAPI web server for CypherFramework."""
    
    def __init__(self, framework, host: str = "127.0.0.1", port: int = 8000):
        self.framework = framework
        self.host = host
        self.port = port
        self.app = FastAPI(title="CypherFramework API", version="1.0.0")
        self.websocket_connections: List[WebSocket] = []
        
        self._setup_routes()
        self._setup_middleware()
        self._setup_websocket_handlers()
        
    def _setup_middleware(self):
        """Setup CORS and other middleware."""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.app.get("/api/status")
        async def get_status():
            """Get framework status."""
            # Return current settings from config
            return {
                'framework': {
                    'auto_update': True,
                    'check_interval': 24,
                    'max_sessions': 10,
                    'session_timeout': 3600,
                    'log_level': 'INFO',
                    'enable_logging': True
                },
                'security': {
                    'require_auth': False,
                    'enable_ssl': False,
                    'ssl_cert_path': '',
                    'ssl_key_path': '',
                    'api_key': '',
                    'allowed_ips': '127.0.0.1,192.168.1.0/24'
                },
                'database': {
                    'type': 'sqlite',
                    'path': 'database/cypher.db',
                    'auto_backup': True,
                    'backup_interval': 168,
                    'max_backups': 5
                },
                'network': {
                    'web_host': '127.0.0.1',
                    'web_port': 8000,
                    'api_host': '127.0.0.1',
                    'api_port': 8001,
                    'enable_cors': True,
                    'cors_origins': 'http://localhost:3000'
                },
                'notifications': {
                    'enable_notifications': True,
                    'email_notifications': False,
                    'webhook_url': '',
                    'notify_on_exploit': True,
                    'notify_on_session': True,
                    'notify_on_error': True
                },
                'modules': {
                    'auto_load': True,
                    'custom_paths': '',
                    'enable_custom_modules': True,
                    'verify_signatures': False
                }
            }
            
        @self.app.post("/api/settings")
        async def save_settings(settings: dict):
            """Save framework settings."""
            # In a real implementation, this would save to config file
            logger.info(f"Settings updated: {settings}")
            return {
                "success": True,
                "message": "Settings saved successfully"
            }
            
        @self.app.get("/api/modules")
        async def get_modules():
            """Get all loaded modules."""
            return self.framework.modules
            
        @self.app.get("/api/modules/{module_type}")
        async def get_modules_by_type(module_type: str):
            """Get modules filtered by type."""
            return await self.framework.get_modules_by_type(module_type)
            
        @self.app.post("/api/modules/execute")
        async def execute_module(request: ModuleExecuteRequest):
            """Execute a module."""
            result = await self.framework.run_module(request.module_name, request.options)
            
            # Broadcast to WebSocket clients
            await self._broadcast_websocket({
                "type": "module_executed",
                "data": {
                    "module": request.module_name,
                    "result": result
                }
            })
            
            return result
            
        @self.app.post("/api/payloads/build")
        async def build_payload(request: PayloadBuildRequest):
            """Build a payload."""
            try:
                payload = await self.framework.build_payload(
                    os=request.os,
                    arch=request.arch,
                    payload_type=request.payload_type,
                    lhost=request.lhost,
                    lport=request.lport,
                    encoder=request.encoder
                )
                
                return {
                    "success": True,
                    "payload": payload.hex(),
                    "size": len(payload)
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }
                
        @self.app.get("/api/sessions")
        async def get_sessions():
            """Get all active sessions."""
            return await self.framework.list_sessions()
            
        @self.app.post("/api/sessions/{session_id}/execute")
        async def execute_session_command(session_id: str, request: SessionCommandRequest):
            """Execute command on a session."""
            result = await self.framework.execute_on_session(session_id, request.command)
            
            # Broadcast to WebSocket clients
            await self._broadcast_websocket({
                "type": "session_command",
                "data": {
                    "session_id": session_id,
                    "command": request.command,
                    "result": result
                }
            })
            
            return result
            
        @self.app.get("/api/targets")
        async def get_targets():
            """Get discovered targets."""
            return await self.framework.get_targets()
            
        @self.app.get("/api/vulnerabilities")
        async def get_vulnerabilities():
            """Get discovered vulnerabilities."""
            return await self.framework.get_vulnerabilities()
            
        @self.app.post("/api/exploits/match")
        async def match_exploits(target_info: Dict):
            """Find matching exploits for a target."""
            return await self.framework.match_exploits(target_info)
            
    def _setup_websocket_handlers(self):
        """Setup WebSocket handlers."""
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.websocket_connections.append(websocket)
            
            try:
                # Subscribe to framework events
                await self.framework.session_manager.subscribe_to_events(
                    self._handle_framework_event
                )
                
                # Send initial status
                await websocket.send_json({
                    "type": "connected",
                    "data": {
                        "stats": await self.framework.get_statistics(),
                        "sessions": await self.framework.list_sessions()
                    }
                })
                
                # Keep connection alive
                while True:
                    data = await websocket.receive_text()
                    message = json.loads(data)
                    
                    # Handle client messages
                    await self._handle_websocket_message(websocket, message)
                    
            except WebSocketDisconnect:
                self.websocket_connections.remove(websocket)
                
    async def _handle_framework_event(self, event_type: str, data: Dict):
        """Handle framework events and broadcast to clients."""
        await self._broadcast_websocket({
            "type": event_type,
            "data": data
        })
        
    async def _handle_websocket_message(self, websocket: WebSocket, message: Dict):
        """Handle incoming WebSocket messages."""
        msg_type = message.get("type")
        
        if msg_type == "ping":
            await websocket.send_json({"type": "pong"})
        elif msg_type == "get_sessions":
            sessions = await self.framework.list_sessions()
            await websocket.send_json({
                "type": "sessions_update",
                "data": sessions
            })
            
    async def _broadcast_websocket(self, message: Dict):
        """Broadcast message to all connected WebSocket clients."""
        if not self.websocket_connections:
            return
            
        # Send to all connections
        for connection in self.websocket_connections.copy():
            try:
                await connection.send_json(message)
            except:
                # Remove disconnected clients
                self.websocket_connections.remove(connection)
                
    async def start(self):
        """Start the web server."""
        logger.info(f"Starting web server on {self.host}:{self.port}")
        
        config = uvicorn.Config(
            app=self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )
        
        server = uvicorn.Server(config)
        await server.serve()