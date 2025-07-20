"""
Dynamic Module Loader
Automatically discovers and loads framework modules.
"""

import importlib.util
import logging
from pathlib import Path
from typing import Dict, List, Any
import inspect

logger = logging.getLogger(__name__)

class ModuleLoader:
    """Loads and manages framework modules dynamically."""
    
    def __init__(self):
        self.loaded_modules = {}
        self.module_cache = {}
        
    async def load_from_directory(self, directory: Path):
        """Load all modules from a directory."""
        logger.info(f"Loading modules from {directory}")
        
        for py_file in directory.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
                
            try:
                await self._load_module_file(py_file)
            except Exception as e:
                logger.error(f"Failed to load module {py_file}: {e}")
                
    async def _load_module_file(self, module_file: Path):
        """Load a single module file."""
        module_name = module_file.stem
        spec = importlib.util.spec_from_file_location(module_name, module_file)
        
        if spec is None or spec.loader is None:
            return
            
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find module classes
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if self._is_framework_module(obj):
                await self._register_module(obj, module_file)
                
    def _is_framework_module(self, cls) -> bool:
        """Check if class is a framework module."""
        # Check for required attributes and methods
        required_attrs = ['name', 'description', 'run']
        return all(hasattr(cls, attr) for attr in required_attrs)
        
    async def _register_module(self, module_class, file_path: Path):
        """Register a module class."""
        try:
            instance = module_class()
            module_info = {
                'name': getattr(instance, 'name', 'Unknown'),
                'description': getattr(instance, 'description', ''),
                'type': getattr(instance, 'module_type', 'unknown'),
                'author': getattr(instance, 'author', 'Unknown'),
                'version': getattr(instance, 'version', '1.0'),
                'file_path': str(file_path),
                'instance': instance,
                'class': module_class
            }
            
            self.loaded_modules[module_info['name']] = module_info
            logger.debug(f"Registered module: {module_info['name']}")
            
        except Exception as e:
            logger.error(f"Failed to register module {module_class.__name__}: {e}")
            
    def get_module(self, name: str) -> Dict:
        """Get a specific module by name."""
        return self.loaded_modules.get(name)
        
    def get_all_modules(self) -> Dict[str, Dict]:
        """Get all loaded modules."""
        return self.loaded_modules.copy()
        
    def get_modules_by_type(self, module_type: str) -> List[Dict]:
        """Get modules filtered by type."""
        return [
            module for module in self.loaded_modules.values()
            if module.get('type') == module_type
        ]
        
    async def reload_module(self, name: str):
        """Reload a specific module."""
        if name not in self.loaded_modules:
            raise ValueError(f"Module {name} not found")
            
        module_info = self.loaded_modules[name]
        file_path = Path(module_info['file_path'])
        
        # Remove old module
        del self.loaded_modules[name]
        
        # Reload
        await self._load_module_file(file_path)
        
    async def unload_module(self, name: str):
        """Unload a module."""
        if name in self.loaded_modules:
            del self.loaded_modules[name]
            logger.info(f"Unloaded module: {name}")