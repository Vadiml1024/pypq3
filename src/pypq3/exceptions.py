"""
Custom exceptions for PyPQ3.
"""


class PQ3Error(Exception):
    """Base exception class for all PQ3-related errors."""
    pass


class KeyExchangeError(PQ3Error):
    """Raised when key exchange operations fail."""
    pass


class CryptographicError(PQ3Error):
    """Raised when cryptographic operations fail."""
    pass


class ProtocolStateError(PQ3Error):
    """Raised when protocol state is invalid or corrupted."""
    pass


class MessageDecodeError(PQ3Error):
    """Raised when message decoding fails."""
    pass