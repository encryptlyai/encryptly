"""
Encryptly SDK - Configuration Management
"""

import os
import base64
from typing import Dict, Optional


def load_active_keys() -> Dict[str, str]:
    """
    Load active keys from ENCRYPTLY_KEYS environment variable.
    
    Format: KID1:base64secret1,KID2:base64secret2,...
    
    Returns:
        Dict mapping kid to decoded secret
       
    Raises:
        ValueError: If ENCRYPTLY_KEYS format is invalid
    """
    keys_env = os.getenv("ENCRYPTLY_KEYS")
    if not keys_env:
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
            
            # Decode base64 secret
            try:
                secret = base64.b64decode(encoded_secret).decode('utf-8')
            except Exception as e:
                raise ValueError(f"Invalid base64 encoding for kid '{kid}': {e}")
            
            active_keys[kid] = secret
    
    except Exception as e:
        raise ValueError(f"Invalid ENCRYPTLY_KEYS format: {e}")
    
    return active_keys


def get_first_key(active_keys: Dict[str, str]) -> Optional[str]:
    """
    Get the first key from active keys dict.
    
    Args:
        active_keys: Dict of kid to secret mappings
        
    Returns:
        First secret, or None if no keys available
    """
    if not active_keys:
        return None
    
    return next(iter(active_keys.values()))


def get_key_by_kid(active_keys: Dict[str, str], kid: str) -> Optional[str]:
    """
    Get secret by kid.
    
    Args:
        active_keys: Dict of kid to secret mappings
        kid: Key ID to look up
        
    Returns:
        Secret for the given kid, or None if not found
    """
    return active_keys.get(kid)


# Global active keys cache
ACTIVE_KEYS = load_active_keys() 