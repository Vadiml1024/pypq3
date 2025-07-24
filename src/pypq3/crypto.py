"""
Core cryptographic primitives for PQ3 protocol implementation.
"""

import os
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

try:
    import kyber_py.kyber as kyber
except ImportError:
    kyber = None

from .exceptions import CryptographicError


class KeyPair:
    """Represents a hybrid key pair (ECC + Kyber post-quantum)."""
    
    def __init__(self, ecc_private_key: ec.EllipticCurvePrivateKey, 
                 kyber_public_key: bytes, kyber_private_key: bytes):
        self.ecc_private_key = ecc_private_key
        self.ecc_public_key = ecc_private_key.public_key()
        self.kyber_public_key = kyber_public_key
        self.kyber_private_key = kyber_private_key
    
    @classmethod
    def generate(cls) -> 'KeyPair':
        """Generate a new hybrid key pair."""
        ecc_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        if kyber is None:
            raise CryptographicError("Kyber library not available")
        
        kyber_public_key, kyber_private_key = kyber.Kyber1024.keygen()
        
        return cls(ecc_private_key, kyber_public_key, kyber_private_key)
    
    def get_ecc_public_bytes(self) -> bytes:
        """Get ECC public key as bytes."""
        return self.ecc_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def get_kyber_public_bytes(self) -> bytes:
        """Get Kyber public key as bytes."""
        return self.kyber_public_key


class SharedSecret:
    """Represents a shared secret derived from hybrid key exchange."""
    
    def __init__(self, ecc_shared: bytes, kyber_shared: bytes):
        self.ecc_shared = ecc_shared
        self.kyber_shared = kyber_shared
        self._combined_secret = self._combine_secrets()
    
    def _combine_secrets(self) -> bytes:
        """Combine ECC and Kyber shared secrets using HKDF."""
        combined = self.ecc_shared + self.kyber_shared
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=b"PQ3-hybrid-secret",
            backend=default_backend()
        )
        return hkdf.derive(combined)
    
    @property
    def secret(self) -> bytes:
        """Get the combined shared secret."""
        return self._combined_secret


class PQ3Crypto:
    """Core cryptographic operations for PQ3 protocol."""
    
    @staticmethod
    def perform_key_exchange_initiator(local_keypair: KeyPair, 
                                     remote_ecc_public: bytes,
                                     remote_kyber_public: bytes) -> Tuple[SharedSecret, bytes]:
        """Perform hybrid key exchange as initiator (returns shared secret and kyber ciphertext)."""
        try:
            # ECC key exchange
            remote_ecc_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), remote_ecc_public
            )
            ecc_shared = local_keypair.ecc_private_key.exchange(
                ec.ECDH(), remote_ecc_key
            )
            
            # Kyber encapsulation (create ciphertext and shared secret)
            if kyber is None:
                raise CryptographicError("Kyber library not available")
            
            kyber_shared, kyber_ciphertext = kyber.Kyber1024.encaps(remote_kyber_public)
            
            return SharedSecret(ecc_shared, kyber_shared), kyber_ciphertext
            
        except Exception as e:
            raise CryptographicError(f"Key exchange failed: {e}") from e
    
    @staticmethod
    def perform_key_exchange_responder(local_keypair: KeyPair, 
                                     remote_ecc_public: bytes,
                                     kyber_ciphertext: bytes) -> SharedSecret:
        """Perform hybrid key exchange as responder (decapsulate kyber ciphertext)."""
        try:
            # ECC key exchange
            remote_ecc_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), remote_ecc_public
            )
            ecc_shared = local_keypair.ecc_private_key.exchange(
                ec.ECDH(), remote_ecc_key
            )
            
            # Kyber decapsulation
            if kyber is None:
                raise CryptographicError("Kyber library not available")
            
            kyber_shared = kyber.Kyber1024.decaps(
                local_keypair.kyber_private_key, kyber_ciphertext
            )
            
            return SharedSecret(ecc_shared, kyber_shared)
            
        except Exception as e:
            raise CryptographicError(f"Key exchange failed: {e}") from e
    
    @staticmethod
    def derive_message_key(shared_secret: SharedSecret, 
                          context: bytes = b"") -> bytes:
        """Derive message encryption key from shared secret."""
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=b"PQ3-message-key" + context,
            backend=default_backend()
        )
        return hkdf.derive(shared_secret.secret)
    
    @staticmethod
    def encrypt_message(key: bytes, plaintext: bytes, 
                       additional_data: Optional[bytes] = None) -> bytes:
        """Encrypt message using ChaCha20-Poly1305."""
        try:
            cipher = ChaCha20Poly1305(key)
            nonce = os.urandom(12)
            ciphertext = cipher.encrypt(nonce, plaintext, additional_data)
            return nonce + ciphertext
        except Exception as e:
            raise CryptographicError(f"Encryption failed: {e}") from e
    
    @staticmethod
    def decrypt_message(key: bytes, encrypted_data: bytes,
                       additional_data: Optional[bytes] = None) -> bytes:
        """Decrypt message using ChaCha20-Poly1305."""
        try:
            if len(encrypted_data) < 12:
                raise CryptographicError("Invalid encrypted data length")
            
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, ciphertext, additional_data)
        except Exception as e:
            raise CryptographicError(f"Decryption failed: {e}") from e
    
    @staticmethod
    def hash_data(data: bytes) -> bytes:
        """Hash data using SHA-384."""
        return hashlib.sha384(data).digest()
    
    @staticmethod
    def secure_random(length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(length)