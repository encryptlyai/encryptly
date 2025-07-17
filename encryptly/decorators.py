"""
AgentVault SDK - Decorators for Easy Authentication
"""

import functools
import inspect
from typing import Callable, Any, Optional
from .exceptions import AuthenticationError, KeyRotationError, VerificationError


def requires_auth(vault_instance: Any, token_param: str = "token", memoize: bool = False):
    """
    Decorator to require authentication for agent methods.
    
    Args:
        vault_instance: The AgentVault instance to use for verification
        token_param: Parameter name containing the authentication token
        memoize: Whether to cache successful verifications (default: False)
       
    Note:
        The decorated function must supply token as a keyword argument,
        or the decorator will detect the token parameter by name in positional arguments.
        Token must be passed as kwarg or as a positional argument with the correct parameter name.
       
    Example:
        ```python
        @requires_auth(vault, "auth_token")
        def sensitive_method(self, data, auth_token):
            # This method requires valid authentication
            return process_data(data)
        ```
    """
    def decorator(func: Callable) -> Callable:
        # Get function signature for parameter detection
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())
        
        # Optional memoization for successful verifications
        if memoize:
            @functools.lru_cache(maxsize=256)
            def verify_token_cached(token: str) -> tuple[bool, Optional[dict]]:
                return vault_instance.verify(token)
        else:
            verify_token_cached = vault_instance.verify
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get token from parameters
            token = kwargs.get(token_param)
            if not token and args and token_param in param_names:
                idx = param_names.index(token_param)
                if idx < len(args):
                    token = args[idx]
            
            if not token:
                raise AuthenticationError(f"Missing required parameter: {token_param}")
            
            # Verify token
            try:
                verified, meta = verify_token_cached(token)
            except KeyRotationError as e:
                raise AuthenticationError("key rotation failure") from e
            except VerificationError as e:
                raise AuthenticationError("bad signature") from e
            
            if not verified:
                raise AuthenticationError("Invalid or expired authentication token")
            
            # Add agent info to kwargs for use in the method
            kwargs["_agent_info"] = meta
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def secure_agent(vault_instance: Any, agent_id: str, role: str, agent_class: str):
    """
    Class decorator to automatically secure an agent class.
    
    Args:
        vault_instance: The AgentVault instance to use
        agent_id: Unique identifier for the agent
        role: Role of the agent (e.g., "DataAnalyst")
        agent_class: Class name for verification
        
    Example:
        ```python
        @secure_agent(vault, "analyst-001", "DataAnalyst", "MyAnalyst")
        class MyAnalyst:
            def analyze_data(self, data):
                return "analysis results"
        ```
    """
    def decorator(cls):
        # Register agent and get token
        token = vault_instance.register(agent_id, role, agent_class)
        
        # Store token as class attribute
        cls._vault_token = token
        cls._vault_instance = vault_instance
        cls._agent_id = agent_id
        
        # Add verification method to class
        def verify_self(self) -> bool:
            """Verify this agent's authentication."""
            is_valid, _ = self._vault_instance.verify(self._vault_token)
            return is_valid
        
        def get_token(self) -> str:
            """Get this agent's authentication token."""
            return self._vault_token
        
        def rotate_token(self) -> str:
            """Rotate this agent's token."""
            self._vault_token = self._vault_instance.rotate_token(self._vault_token)
            return self._vault_token
        
        # Add methods to class
        cls.verify_self = verify_self
        cls.get_token = get_token
        cls.rotate_token = rotate_token
        
        return cls
    return decorator


def verify_caller(vault_instance: Any, token_param: str = "caller_token"):
    """
    Decorator to verify the caller's identity before executing a method.
    
    Args:
        vault_instance: The AgentVault instance to use for verification
        token_param: Parameter name containing the caller's token
        
    Example:
        ```python
        @verify_caller(vault, "caller_token")
        def receive_data(self, data, caller_token):
            # Only authenticated agents can call this method
            return "data received"
        ```
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get caller token from parameters
            caller_token = kwargs.get(token_param)
            if not caller_token:
                raise AuthenticationError(f"Missing required parameter: {token_param}")
            
            # Verify caller token
            try:
                verified, meta = vault_instance.verify(caller_token)
            except KeyRotationError as e:
                raise AuthenticationError("key rotation failure") from e
            except VerificationError as e:
                raise AuthenticationError("bad signature") from e
            
            if not verified:
                raise AuthenticationError("Invalid caller authentication token")
            
            # Add caller info to kwargs
            kwargs["_caller_info"] = meta
           
            return func(*args, **kwargs)
        return wrapper
    return decorator 