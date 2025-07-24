"""
PyPQ3: Python implementation of Apple's PQ3 post-quantum cryptography protocol.

This package provides a comprehensive implementation of the PQ3 protocol,
including key exchange, message encryption/decryption, and state management.
"""

__version__ = "0.1.0"
__author__ = "Your Name"

from .core import PQ3Protocol, PQ3Session, PQ3Message
from .crypto import KeyPair, SharedSecret
from .protocol import DeviceIdentity, PQ3KeyExchange
from .ratchet import PQ3Ratchet
from .exceptions import PQ3Error, KeyExchangeError, CryptographicError, ProtocolStateError, MessageDecodeError

__all__ = [
    "PQ3Protocol",
    "PQ3Session",
    "PQ3Message",
    "KeyPair", 
    "SharedSecret",
    "DeviceIdentity",
    "PQ3KeyExchange",
    "PQ3Ratchet",
    "PQ3Error",
    "KeyExchangeError", 
    "CryptographicError",
    "ProtocolStateError",
    "MessageDecodeError",
]