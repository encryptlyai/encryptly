"""
Encryptly SDK - Custom Exceptions
"""


class EncryptlyError(Exception):
    """Base exception for all Encryptly errors."""
    pass


class TokenError(EncryptlyError):
    """Raised when there's an issue with token operations."""
    pass


class VerificationError(EncryptlyError):
    """Raised when verification fails."""
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