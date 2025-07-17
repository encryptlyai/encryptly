"""
Encryptly SDK - Custom Exceptions
"""


class EncryptlyError(Exception):
    """Base exception for all Encryptly errors."""
    def __str__(self) -> str:
        return self.args[0] if self.args else super().__str__()


class TokenError(EncryptlyError):
    """Raised when there's an issue with token operations."""
    pass


class RegistrationError(EncryptlyError):
    """Raised when agent registration fails."""
    pass


class AuthenticationError(EncryptlyError):
    """Raised when authentication fails."""
    pass


class KeyRotationError(EncryptlyError):
    """Raised when key rotation operations fail."""
    pass


class VerificationError(EncryptlyError):
    """Raised when verification fails."""
    pass 

__all__ = [
    "EncryptlyError",
    "TokenError",
    "VerificationError",
    "RegistrationError",
    "AuthenticationError",
    "KeyRotationError",
]