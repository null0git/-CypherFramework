"""
Base Auxiliary Module Template
All auxiliary modules should inherit from this base class.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class BaseAuxiliary(ABC):
    """Base class for all auxiliary modules."""
    
    # Module metadata
    name = "Unknown Auxiliary"
    description = "Base auxiliary template"
    author = "Unknown"
    version = "1.0"
    module_type = "auxiliary"
    
    # Auxiliary-specific metadata
    category = "scanner"  # scanner, brute, fuzz, dos, gather
    
    def __init__(self):
        self.options = self._default_options()
        self.required_options = self._required_options()
        
    @abstractmethod
    def _default_options(self) -> Dict[str, Any]:
        """Return default options for this auxiliary module."""
        return {
            'RHOSTS': {'value': '', 'required': True, 'description': 'Target host(s)'},
            'THREADS': {'value': 10, 'required': False, 'description': 'Number of threads'},
            'TIMEOUT': {'value': 10, 'required': False, 'description': 'Connection timeout'},
        }
        
    @abstractmethod
    def _required_options(self) -> List[str]:
        """Return list of required option names."""
        return ['RHOSTS']
        
    @abstractmethod
    async def run(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the auxiliary module.
        
        Args:
            options: Module options
            
        Returns:
            Dict with results
        """
        pass
        
    def set_option(self, name: str, value: Any):
        """Set an option value."""
        if name in self.options:
            self.options[name]['value'] = value
        else:
            raise ValueError(f"Unknown option: {name}")
            
    def get_option(self, name: str) -> Any:
        """Get an option value."""
        if name in self.options:
            return self.options[name]['value']
        raise ValueError(f"Unknown option: {name}")
        
    def get_info(self) -> Dict[str, Any]:
        """Get auxiliary module information."""
        return {
            'name': self.name,
            'description': self.description,
            'author': self.author,
            'version': self.version,
            'category': self.category,
            'options': self.options
        }