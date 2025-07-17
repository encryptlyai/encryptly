"""
Encryptly SDK - Configuration Management
"""

import os
import base64
import warnings
from typing import Dict, Optional


def load_active_keys() -> Dict[str, bytes]:
    """
    Load active keys from ENCRYPTLY_KEYS environment variable.
    
    Format: KID1:base64secret1,KID2:base64secret2,...
    
    Returns:
        Dict mapping kid to decoded secret bytes
        
    Raises:
        ValueError: If ENCRYPTLY_KEYS format is invalid
    """
    keys_env = os.getenv("ENCRYPTLY_KEYS")
    if not keys_env:
        warnings.warn("ENCRYPTLY_KEYS environment variable not set", UserWarning)
        return {}
    
    active_keys = {}
    
    try:
        for key_pair in keys_env.split(","):
            if ":" not in key_pair:
                raise ValueError(f"Invalid key pair format: {key_pair}")
            
            kid, encoded_secret = key_pair.split(":", 1)
            kid = kid.strip()
            encoded_secret = encoded_secret.strip()
            
            if not kid or not encoded_secret:
                raise ValueError(f"Empty kid or secret in: {key_pair}")
            
            # Check for duplicate kid
            if kid in active_keys:
                raise ValueError(f"Duplicate key ID: {kid}")
            
            # Decode base64 secret and keep as bytes
            try:
                secret_bytes = base64.b64decode(encoded_secret)  # keep bytes
                if len(secret_bytes) < 32:
                    raise ValueError(f"secret for {kid} too short")
                active_keys[kid] = secret_bytes
            except Exception as e:
                raise ValueError(f"Invalid base64 encoding for kid '{kid}': {e}")
    
    except Exception as e:
        raise ValueError(f"Invalid ENCRYPTLY_KEYS format: {e}")
    
    return active_keys


def _deprecated_get_first_key(active_keys: Dict[str, bytes]) -> Optional[bytes]:
    """
    DEPRECATED — will be removed in v0.2.

    Historically returned the *first secret* from the active‐keys dictionary.
    New code should instead call ``get_default_kid()`` to retrieve the *kid*
    and then fetch the secret via ``get_secret()``.

    Args:
        active_keys: Dict of kid → secret‐bytes mappings.

    Returns:
        The first secret (``bytes``) if any keys exist, otherwise ``None``.

    Raises:
        DeprecationWarning: Always, to alert callers at runtime.
    """
    warnings.warn(
        "_deprecated_get_first_key() is deprecated; "
        "use get_default_kid() / get_secret() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    if not active_keys:
        return None
    return next(iter(active_keys.values()))


# Backward‑compatibility alias — will be removed in v0.2
get_first_key = _deprecated_get_first_key


def get_key_by_kid(active_keys: Dict[str, bytes], kid: str) -> Optional[bytes]:
    """
    Get secret by kid.
    
    Args:
        active_keys: Dict of kid to secret mappings
        kid: Key ID to look up
        
    Returns:
        Secret bytes for the given kid, or None if not found
    """
    return active_keys.get(kid)


def get_default_kid(active_keys: Dict[str, bytes]) -> Optional[str]:
    """
    Get the default kid (first key in the dict).
    
    Args:
        active_keys: Dict of kid to secret mappings
        
    Returns:
        First kid, or None if no keys available
    """
    if not active_keys:
        return None
    
    return next(iter(active_keys.keys()))


def get_secret(active_keys: Dict[str, bytes], kid: str) -> bytes:
    """
    Get secret as bytes for the given kid.
    
    Args:
        active_keys: Dict of kid to secret mappings
        kid: Key ID to look up
        
    Returns:
        Secret bytes
        
    Raises:
        KeyError: If kid not found
    """
    secret = active_keys.get(kid)
    if not secret:
        raise KeyError(f"Unknown key ID: {kid}")
    
    return secret  # already bytes


# Global active keys cache
ACTIVE_KEYS = load_active_keys()

__all__ = [
    "ACTIVE_KEYS",
    "load_active_keys",
    "get_key_by_kid",
    "get_default_kid",
    "get_secret",
    # Deprecated — slated for removal in v0.2
    "get_first_key",
]