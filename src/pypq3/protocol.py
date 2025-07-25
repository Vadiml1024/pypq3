"""
PQ3 protocol key exchange and initialization implementation.
"""

import json
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass

from .crypto import KeyPair, SharedSecret, PQ3Crypto
from .exceptions import KeyExchangeError


@dataclass
class DeviceIdentity:
    """Device identity information for PQ3 protocol."""

    device_id: str
    ecc_public_key: bytes
    kyber_public_key: bytes
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "device_id": self.device_id,
            "ecc_public_key": self.ecc_public_key.hex(),
            "kyber_public_key": self.kyber_public_key.hex(),
            "signature": self.signature.hex() if self.signature else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceIdentity":
        """Create from dictionary."""
        return cls(
            device_id=data["device_id"],
            ecc_public_key=bytes.fromhex(data["ecc_public_key"]),
            kyber_public_key=bytes.fromhex(data["kyber_public_key"]),
            signature=(
                bytes.fromhex(data["signature"]) if data.get("signature") else None
            ),
        )


@dataclass
class InitialKeyExchange:
    """Initial key exchange message for PQ3."""

    sender_identity: DeviceIdentity
    ephemeral_ecc_public: bytes
    kyber_ciphertext: bytes
    timestamp: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "sender_identity": self.sender_identity.to_dict(),
            "ephemeral_ecc_public": self.ephemeral_ecc_public.hex(),
            "kyber_ciphertext": self.kyber_ciphertext.hex(),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InitialKeyExchange":
        """Create from dictionary."""
        return cls(
            sender_identity=DeviceIdentity.from_dict(data["sender_identity"]),
            ephemeral_ecc_public=bytes.fromhex(data["ephemeral_ecc_public"]),
            kyber_ciphertext=bytes.fromhex(data["kyber_ciphertext"]),
            timestamp=data["timestamp"],
        )


class PQ3KeyExchange:
    """PQ3 protocol key exchange implementation."""

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.identity_keypair = KeyPair.generate()
        self.device_identity = DeviceIdentity(
            device_id=device_id,
            ecc_public_key=self.identity_keypair.get_ecc_public_bytes(),
            kyber_public_key=self.identity_keypair.get_kyber_public_bytes(),
        )

    def initiate_key_exchange(
        self, remote_identity: DeviceIdentity
    ) -> Tuple[InitialKeyExchange, SharedSecret]:
        """Initiate key exchange with remote device."""
        try:
            # Generate ephemeral keypair
            ephemeral_keypair = KeyPair.generate()

            # Perform key agreement with remote identity keys
            (
                identity_shared,
                identity_kyber_ct,
            ) = PQ3Crypto.perform_key_exchange_initiator(
                self.identity_keypair,
                remote_identity.ecc_public_key,
                remote_identity.kyber_public_key,
            )

            # Perform ephemeral key exchange
            (
                ephemeral_shared,
                ephemeral_kyber_ct,
            ) = PQ3Crypto.perform_key_exchange_initiator(
                ephemeral_keypair,
                remote_identity.ecc_public_key,
                remote_identity.kyber_public_key,
            )

            # Combine shared secrets
            combined_secret = self._combine_shared_secrets(
                identity_shared, ephemeral_shared
            )

            # Create key exchange message with ephemeral Kyber ciphertext
            import time

            key_exchange = InitialKeyExchange(
                sender_identity=self.device_identity,
                ephemeral_ecc_public=ephemeral_keypair.get_ecc_public_bytes(),
                kyber_ciphertext=ephemeral_kyber_ct,
                timestamp=int(time.time()),
            )

            return key_exchange, combined_secret

        except Exception as e:
            raise KeyExchangeError(f"Key exchange initiation failed: {e}") from e

    def respond_to_key_exchange(
        self, key_exchange: InitialKeyExchange
    ) -> Tuple[InitialKeyExchange, SharedSecret]:
        """Respond to incoming key exchange."""
        try:
            # Verify sender identity (simplified)
            sender_identity = key_exchange.sender_identity

            # Perform identity key agreement
            (
                identity_shared,
                identity_kyber_ct,
            ) = PQ3Crypto.perform_key_exchange_initiator(
                self.identity_keypair,
                sender_identity.ecc_public_key,
                sender_identity.kyber_public_key,
            )

            # Perform ephemeral key agreement (responder side)
            ephemeral_shared = PQ3Crypto.perform_key_exchange_responder(
                self.identity_keypair,
                key_exchange.ephemeral_ecc_public,
                key_exchange.kyber_ciphertext,
            )

            # Combine shared secrets
            combined_secret = self._combine_shared_secrets(
                identity_shared, ephemeral_shared
            )

            # Create response
            temp_keypair = KeyPair.generate()
            import time

            response = InitialKeyExchange(
                sender_identity=self.device_identity,
                ephemeral_ecc_public=temp_keypair.get_ecc_public_bytes(),
                kyber_ciphertext=identity_kyber_ct,
                timestamp=int(time.time()),
            )

            return response, combined_secret

        except Exception as e:
            raise KeyExchangeError(f"Key exchange response failed: {e}") from e

    def _combine_shared_secrets(
        self, identity_shared: SharedSecret, ephemeral_shared: SharedSecret
    ) -> SharedSecret:
        """Combine identity and ephemeral shared secrets."""
        combined_ecc = PQ3Crypto.hash_data(
            identity_shared.ecc_shared + ephemeral_shared.ecc_shared
        )
        combined_kyber = PQ3Crypto.hash_data(
            identity_shared.kyber_shared + ephemeral_shared.kyber_shared
        )
        return SharedSecret(combined_ecc, combined_kyber)

    def serialize_identity(self) -> str:
        """Serialize device identity to JSON."""
        return json.dumps(self.device_identity.to_dict())

    @classmethod
    def deserialize_identity(cls, data: str) -> DeviceIdentity:
        """Deserialize device identity from JSON."""
        return DeviceIdentity.from_dict(json.loads(data))

    def get_public_identity(self) -> DeviceIdentity:
        """Get public identity for sharing."""
        return self.device_identity
