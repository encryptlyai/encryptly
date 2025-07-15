"""
Encryptly SDK - Main Authentication System
"""

import jwt
import hashlib
import hmac
import secrets
import time
import json
from typing import Dict, Optional, Tuple, Any
from datetime import datetime, timedelta

from .exceptions import EncryptlyError, TokenError, VerificationError


class Encryptly:
    """
    Encryptly - Secure Authentication for AI Agents
    
    Simple API for developers to add authentication to multi-agent systems.
    
    Example:
        ```python
        vault = Encryptly()
        token = vault.register("my-agent", "DataAnalyst", "MyAgent")
        is_valid, info = vault.verify(token)
        ```
    """
    
    def __init__(self, secret_key: Optional[str] = None, token_expiry_hours: int = 24):
        """
        Initialize AgentVault.
        
        Args:
            secret_key: Optional secret key for JWT signing. Auto-generated if None.
            token_expiry_hours: How long tokens remain valid (default: 24 hours)
        """
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = "HS256"
        self.token_expiry_hours = token_expiry_hours
        self.issued_tokens: Dict[str, Dict] = {}
        self.agent_registry: Dict[str, Dict] = {}
        self.audit_log = []
        
        print(f"Encryptly initialized (token expiry: {token_expiry_hours}h)")
    
    def register(self, agent_id: str, role: str, agent_class: str) -> str:
        """
        Register an agent and get authentication token.
        
        Args:
            agent_id: Unique identifier for your agent
            role: What the agent does (e.g., "DataAnalyst", "RiskAdvisor")
            agent_class: Python class name for verification
            
        Returns:
            str: Authentication token for the agent
            
        Raises:
            AgentVaultError: If agent already registered
            
        Example:
            ```python
            token = vault.register("analyst-001", "DataAnalyst", "MyAnalystAgent")
            ```
        """
        if agent_id in self.agent_registry:
            raise EncryptlyError(f"Agent {agent_id} already registered")
        
        # Generate unique agent hash for integrity
        agent_hash = hashlib.sha256(f"{agent_id}:{role}:{agent_class}".encode()).hexdigest()
        
        # Store agent registration
        self.agent_registry[agent_id] = {
            "role": role,
            "class": agent_class,
            "hash": agent_hash,
            "registered_at": datetime.now().isoformat(),
            "status": "active"
        }
        
        # Issue initial token
        token = self._issue_token(agent_id)
        
        # Audit log
        self._log_event("AGENT_REGISTERED", agent_id, {"role": role, "class": agent_class})
        
        print(f"Agent registered: {agent_id} ({role})")
        return token
    
    def verify(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """
        Verify if a token is authentic and valid.
        
        Args:
            token: JWT token to verify
            
        Returns:
            Tuple[bool, Optional[Dict]]: (is_valid, agent_info)
            
        Example:
            ```python
            is_valid, info = vault.verify(token)
            if is_valid:
                print(f"Verified agent: {info['agent_id']} ({info['role']})")
            ```
        """
        try:
            # Decode and verify JWT
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if token is still active
            token_id = payload.get("jti")
            if token_id and token_id in self.issued_tokens:
                token_info = self.issued_tokens[token_id]
                if token_info["status"] != "active":
                    self._log_event("TOKEN_VERIFICATION_FAILED", payload.get("agent_id"), 
                                  {"reason": "token_revoked", "token_id": token_id})
                    return False, None
            
            # Verify agent is still registered
            agent_id = payload.get("agent_id")
            if agent_id not in self.agent_registry:
                self._log_event("TOKEN_VERIFICATION_FAILED", agent_id, 
                              {"reason": "agent_not_registered"})
                return False, None
            
            # Verify agent hash for integrity
            agent_info = self.agent_registry[agent_id]
            if payload.get("agent_hash") != agent_info["hash"]:
                self._log_event("TOKEN_VERIFICATION_FAILED", agent_id, 
                              {"reason": "agent_hash_mismatch"})
                return False, None
            
            self._log_event("TOKEN_VERIFIED", agent_id, {"token_id": token_id})
            
            return True, {
                "agent_id": agent_id,
                "role": payload.get("role"),
                "class": payload.get("class"),
                "token_id": token_id
            }
            
        except jwt.ExpiredSignatureError:
            self._log_event("TOKEN_VERIFICATION_FAILED", "unknown", {"reason": "token_expired"})
            return False, None
        except jwt.InvalidTokenError as e:
            self._log_event("TOKEN_VERIFICATION_FAILED", "unknown", {"reason": f"invalid_token: {str(e)}"})
            return False, None
        except Exception as e:
            self._log_event("TOKEN_VERIFICATION_FAILED", "unknown", {"reason": f"verification_error: {str(e)}"})
            return False, None
    
    def sign_message(self, message: str, sender_token: str) -> Dict[str, Any]:
        """
        Sign a message with agent credentials for integrity verification.
        
        Args:
            message: The message to sign
            sender_token: Token of the sending agent
            
        Returns:
            Dict containing signed message and metadata
            
        Raises:
            TokenError: If sender token is invalid
            
        Example:
            ```python
            signed_msg = vault.sign_message("Hello from Agent A", token)
            ```
        """
        # Verify sender token
        is_valid, agent_info = self.verify(sender_token)
        if not is_valid:
            raise TokenError("Invalid sender token")
        
        # Create message signature
        message_data = {
            "content": message,
            "sender_id": agent_info["agent_id"],
            "sender_role": agent_info["role"],
            "timestamp": datetime.now().isoformat(),
            "message_id": secrets.token_hex(8)
        }
        
        # Sign the message
        message_str = json.dumps(message_data, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(),
            message_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        signed_message = {
            **message_data,
            "signature": signature
        }
        
        self._log_event("MESSAGE_SIGNED", agent_info["agent_id"], {"message_id": message_data["message_id"]})
        
        return signed_message
    
    def verify_message(self, signed_message: Dict[str, Any], sender_token: str = None) -> bool:
        """
        🔍 Verify the authenticity of a signed message.
        
        Args:
            signed_message: The signed message to verify
            sender_token: Optional token to verify sender identity
            
        Returns:
            bool: True if message is authentic
            
        Example:
            ```python
            is_authentic = vault.verify_message(signed_msg, sender_token)
            ```
        """
        try:
            # Extract signature
            signature = signed_message.pop("signature", None)
            if not signature:
                return False
            
            # Recreate message string
            message_str = json.dumps(signed_message, sort_keys=True)
            
            # Verify signature
            expected_signature = hmac.new(
                self.secret_key.encode(),
                message_str.encode(),
                hashlib.sha256
            ).hexdigest()
            
            is_valid = hmac.compare_digest(signature, expected_signature)
            
            # Optional: verify sender token matches message sender
            if sender_token and is_valid:
                token_valid, agent_info = self.verify(sender_token)
                if token_valid:
                    is_valid = is_valid and (agent_info["agent_id"] == signed_message.get("sender_id"))
            
            # Restore signature
            signed_message["signature"] = signature
            
            if is_valid:
                self._log_event("MESSAGE_VERIFIED", signed_message.get("sender_id"), 
                              {"message_id": signed_message.get("message_id")})
            else:
                self._log_event("MESSAGE_VERIFICATION_FAILED", signed_message.get("sender_id", "unknown"), 
                              {"message_id": signed_message.get("message_id")})
            
            return is_valid
            
        except Exception as e:
            self._log_event("MESSAGE_VERIFICATION_ERROR", "unknown", {"error": str(e)})
            return False
    
    def rotate_token(self, old_token: str) -> str:
        """
        Rotate an agent's token for security.
        
        Args:
            old_token: Current token to rotate
            
        Returns:
            str: New authentication token
            
        Raises:
            TokenError: If old token is invalid
        """
        # Verify old token
        is_valid, agent_info = self.verify(old_token)
        if not is_valid:
            raise TokenError("Invalid token for rotation")
        
        # Revoke old token
        self._revoke_token(old_token)
        
        # Issue new token
        new_token = self._issue_token(agent_info["agent_id"])
        
        print(f"Token rotated for agent: {agent_info['agent_id']}")
        return new_token
    
    def unregister(self, agent_id: str) -> bool:
        """
        Unregister an agent and revoke all its tokens.
        
        Args:
            agent_id: ID of agent to unregister
            
        Returns:
            bool: True if successfully unregistered
        """
        if agent_id not in self.agent_registry:
            return False
        
        # Mark agent as inactive
        self.agent_registry[agent_id]["status"] = "inactive"
        
        # Revoke all tokens for this agent
        for token_id, token_info in self.issued_tokens.items():
            if token_info["agent_id"] == agent_id and token_info["status"] == "active":
                token_info["status"] = "revoked"
                token_info["revoked_at"] = datetime.now().isoformat()
        
        self._log_event("AGENT_UNREGISTERED", agent_id, {})
        
        print(f"Agent unregistered: {agent_id}")
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get vault status and statistics.
        
        Returns:
            Dict containing vault statistics
        """
        active_agents = sum(1 for info in self.agent_registry.values() if info["status"] == "active")
        active_tokens = sum(1 for info in self.issued_tokens.values() if info["status"] == "active")
        
        return {
            "total_agents": len(self.agent_registry),
            "active_agents": active_agents,
            "total_tokens": len(self.issued_tokens),
            "active_tokens": active_tokens,
            "audit_events": len(self.audit_log),
            "version": "0.1.0"
        }
    
    def _issue_token(self, agent_id: str) -> str:
        """Issue a new JWT token for an agent."""
        agent_info = self.agent_registry[agent_id]
        
        # Create JWT payload
        payload = {
            "agent_id": agent_id,
            "role": agent_info["role"],
            "class": agent_info["class"],
            "agent_hash": agent_info["hash"],
            "iat": int(time.time()),
            "exp": int(time.time()) + (self.token_expiry_hours * 3600),
            "iss": "AgentVault",
            "jti": secrets.token_hex(8)  # Unique token ID
        }
        
        # Sign the token
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        
        # Store token info
        self.issued_tokens[payload["jti"]] = {
            "agent_id": agent_id,
            "issued_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(hours=self.token_expiry_hours)).isoformat(),
            "status": "active"
        }
        
        self._log_event("TOKEN_ISSUED", agent_id, {"token_id": payload["jti"]})
        
        return token
    
    def _revoke_token(self, token: str) -> bool:
        """Revoke a token to prevent further use."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            token_id = payload.get("jti")
            
            if token_id and token_id in self.issued_tokens:
                self.issued_tokens[token_id]["status"] = "revoked"
                self.issued_tokens[token_id]["revoked_at"] = datetime.now().isoformat()
                
                self._log_event("TOKEN_REVOKED", payload.get("agent_id"), {"token_id": token_id})
                return True
            
            return False
            
        except Exception:
            return False
    
    def _log_event(self, event_type: str, agent_id: str, details: Dict):
        """Log security events for audit purposes."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "agent_id": agent_id,
            "details": details
        }
        self.audit_log.append(event)
        
        # Keep only last 1000 events for MVP
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:] 