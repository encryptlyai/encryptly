"""
Encryptly SDK - Lightweight Authentication for AI Agents
========================================================

A simple, secure way to authenticate AI agents and verify message integrity
in multi-agent systems like CrewAI and LangChain.

Quick Start:
-----------
```python
from encryptly import Encryptly

# Initialize vault
vault = Encryptly()

# Register agent and get token
token = vault.register("my-agent", "DataAnalyst", "MyAgentClass")

# Verify token authenticity
is_valid, info = vault.verify(token)

# Secure agent communication
message = vault.sign_message("Hello from Agent A", token)
is_authentic = vault.verify_message(message, sender_token=token)
```

Features:
---------
✅ Prevents agent impersonation
✅ Cryptographic message integrity
✅ JWT-based authentication
✅ Token rotation and revocation
✅ Audit logging
✅ Framework agnostic (CrewAI, LangChain, etc.)
"""

from .vault import Encryptly
from .decorators import requires_auth, secure_agent
from .integrations import CrewAIIntegration, LangChainIntegration
from .exceptions import EncryptlyError, TokenError, VerificationError

__version__ = "0.1.0"
__author__ = "Encryptly Team"
__all__ = [
    "Encryptly",
    "requires_auth", 
    "secure_agent",
    "CrewAIIntegration",
    "LangChainIntegration",
    "EncryptlyError",
    "TokenError", 
    "VerificationError"
] 