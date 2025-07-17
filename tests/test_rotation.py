"""
Tests for Encryptly key rotation functionality.
"""

import pytest
import os
import base64
import jwt
from unittest.mock import patch

from encryptly.vault import Encryptly
from encryptly.exceptions import KeyRotationError


class TestKeyRotation:
    """Test key rotation functionality."""
   
    def setup_method(self):
        """Set up test environment."""
        # Create test keys
        self.secret1 = "test_secret_1" * 3
        self.secret2 = "test_secret_2" * 3
        self.encoded1 = base64.b64encode(self.secret1.encode()).decode()
        self.encoded2 = base64.b64encode(self.secret2.encode()).decode()
        
        # Set environment variable for key rotation
        os.environ["ENCRYPTLY_KEYS"] = f"v1:{self.encoded1},v2:{self.encoded2}"
        
        # Reload config to pick up new environment
        from encryptly.config import load_active_keys
        active_keys = load_active_keys()
        
        # Create vault with the active keys
        self.vault = Encryptly()
        # Manually set the active keys to ensure they're used
        self.vault.active_keys = active_keys
        if active_keys:
            self.vault.default_kid = list(active_keys.keys())[0]
            self.vault.secret_key = active_keys[self.vault.default_kid]
            
        # Clean up database for fresh test
        import sqlite3
        with sqlite3.connect(self.vault.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM agents")
            cursor.execute("DELETE FROM tokens")
            cursor.execute("DELETE FROM audit_log")
            conn.commit()
    
    def teardown_method(self):
        """Clean up test environment."""
        if "ENCRYPTLY_KEYS" in os.environ:
            del os.environ["ENCRYPTLY_KEYS"]
    
    def test_issue_token_with_key_rotation(self):
        """Test that token issuance works with key rotation."""
        # Register agent
        token = self.vault.register("test-agent", "TestRole", "TestAgent")
        
        # Verify token is valid
        is_valid, info = self.vault.verify(token)
        assert is_valid
        assert info["agent_id"] == "test-agent"
        assert info["role"] == "TestRole"
    
    def test_issue_token_with_specific_kid(self):
        """Test that token issuance works with specific kid."""
        # Register agent with specific kid
        token = self.vault.register("test-agent-2", "TestRole", "TestAgent", kid="v2")
        
        # Verify token is valid
        is_valid, info = self.vault.verify(token)
        assert is_valid
        assert info["agent_id"] == "test-agent-2"
    
    def test_verify_token_with_unknown_kid(self):
        """Test that verification fails with unknown kid."""
        # Register agent
        token = self.vault.register("test-agent-3", "TestRole", "TestAgent")
        
        # Manually tamper the token header to use unknown kid
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        # Create new token with unknown kid
        tampered_token = jwt.encode(
            payload, 
            self.secret1, 
            algorithm="HS256", 
            headers={"kid": "v9"}
        )
        
        # Verify should fail
        is_valid, info = self.vault.verify(tampered_token)
        assert not is_valid
    
    def test_register_with_unknown_kid_raises_error(self):
        """Test that registration with unknown kid raises KeyRotationError."""
        with pytest.raises(KeyRotationError, match="Unknown key ID: v9"):
            self.vault.register("test-agent-4", "TestRole", "TestAgent", kid="v9")
    
    def test_rotate_token_with_key_rotation(self):
        """Test token rotation with key rotation."""
        # Register agent
        token = self.vault.register("test-agent-5", "TestRole", "TestAgent")
        
        # Rotate token
        new_token = self.vault.rotate_token(token)
        
        # Verify new token is valid
        is_valid, info = self.vault.verify(new_token)
        assert is_valid
        assert info["agent_id"] == "test-agent-5"
        
        # Old token should be invalid
        is_valid, info = self.vault.verify(token)
        assert not is_valid
    
    def test_rotate_token_with_specific_kid(self):
        """Test token rotation with specific kid."""
        # Register agent
        token = self.vault.register("test-agent-6", "TestRole", "TestAgent")
        
        # Rotate token with specific kid
        new_token = self.vault.rotate_token(token, kid="v2")
        
        # Verify new token is valid
        is_valid, info = self.vault.verify(new_token)
        assert is_valid
        assert info["agent_id"] == "test-agent-6"
    
    def test_fallback_to_single_key_mode(self):
        """Test fallback to single key mode when no ENCRYPTLY_KEYS."""
        # Remove environment variable
        if "ENCRYPTLY_KEYS" in os.environ:
            del os.environ["ENCRYPTLY_KEYS"]
        
        # Create vault without key rotation
        vault = Encryptly()
        
        # Register agent
        token = vault.register("test-agent-7", "TestRole", "TestAgent")
        
        # Verify token is valid
        is_valid, info = vault.verify(token)
        assert is_valid
        assert info["agent_id"] == "test-agent-7"
    
    def test_invalid_env_format_raises_error(self):
        """Test that invalid ENCRYPTLY_KEYS format raises error."""
        # Set invalid format
        os.environ["ENCRYPTLY_KEYS"] = "invalid_format"
        
        # Should raise ValueError during config loading
        from encryptly.config import load_active_keys
        with pytest.raises(ValueError):
            load_active_keys() 