"""
Main PQ3 protocol implementation providing high-level interface.
"""

import json
import time
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass

from .crypto import SharedSecret
from .protocol import PQ3KeyExchange, DeviceIdentity, InitialKeyExchange
from .ratchet import PQ3Ratchet
from .exceptions import PQ3Error, ProtocolStateError, MessageDecodeError


@dataclass
class PQ3Message:
    """Represents a PQ3 encrypted message."""

    sender_device_id: str
    recipient_device_id: str
    header: bytes
    ciphertext: bytes
    timestamp: int
    message_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "sender_device_id": self.sender_device_id,
            "recipient_device_id": self.recipient_device_id,
            "header": self.header.hex(),
            "ciphertext": self.ciphertext.hex(),
            "timestamp": self.timestamp,
            "message_id": self.message_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PQ3Message":
        """Create from dictionary."""
        return cls(
            sender_device_id=data["sender_device_id"],
            recipient_device_id=data["recipient_device_id"],
            header=bytes.fromhex(data["header"]),
            ciphertext=bytes.fromhex(data["ciphertext"]),
            timestamp=data["timestamp"],
            message_id=data["message_id"],
        )


class PQ3Session:
    """Represents an ongoing PQ3 messaging session between two devices."""

    def __init__(
        self,
        local_device_id: str,
        remote_device_id: str,
        shared_secret: SharedSecret,
        is_initiator: bool = True,
    ):
        self.local_device_id = local_device_id
        self.remote_device_id = remote_device_id
        self.is_initiator = is_initiator
        self.ratchet = PQ3Ratchet(shared_secret, is_initiator)
        self.message_counter = 0
        self.last_activity = time.time()

    def encrypt_message(self, plaintext: str) -> PQ3Message:
        """Encrypt a message for the remote device."""
        try:
            plaintext_bytes = plaintext.encode("utf-8")

            # Create associated data
            associated_data = self._create_associated_data()

            # Encrypt using ratchet
            header, ciphertext = self.ratchet.encrypt_message(
                plaintext_bytes, associated_data
            )

            # Create message
            message = PQ3Message(
                sender_device_id=self.local_device_id,
                recipient_device_id=self.remote_device_id,
                header=header,
                ciphertext=ciphertext,
                timestamp=int(time.time()),
                message_id=f"{self.local_device_id}_{self.message_counter}",
            )

            self.message_counter += 1
            self.last_activity = time.time()

            return message

        except Exception as e:
            raise PQ3Error(f"Message encryption failed: {e}") from e

    def decrypt_message(self, message: PQ3Message) -> str:
        """Decrypt a message from the remote device."""
        try:
            # Verify message is for this session
            if message.recipient_device_id != self.local_device_id:
                raise MessageDecodeError("Message not intended for this device")

            if message.sender_device_id != self.remote_device_id:
                raise MessageDecodeError("Message from unexpected sender")

            # Create associated data
            associated_data = self._create_associated_data()

            # Decrypt using ratchet
            plaintext_bytes = self.ratchet.decrypt_message(
                message.header, message.ciphertext, associated_data
            )

            self.last_activity = time.time()

            return plaintext_bytes.decode("utf-8")

        except Exception as e:
            raise PQ3Error(f"Message decryption failed: {e}") from e

    def _create_associated_data(self) -> bytes:
        """Create associated data for authenticated encryption."""
        return f"{self.local_device_id}:{self.remote_device_id}".encode("utf-8")

    def get_session_info(self) -> Dict[str, Any]:
        """Get session information."""
        return {
            "local_device_id": self.local_device_id,
            "remote_device_id": self.remote_device_id,
            "is_initiator": self.is_initiator,
            "message_counter": self.message_counter,
            "last_activity": self.last_activity,
        }


class PQ3Protocol:
    """Main PQ3 protocol implementation."""

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.key_exchange = PQ3KeyExchange(device_id)
        self.sessions: Dict[str, PQ3Session] = {}
        self.pending_key_exchanges: Dict[
            str, Tuple[InitialKeyExchange, SharedSecret]
        ] = {}

    def get_device_identity(self) -> DeviceIdentity:
        """Get this device's public identity."""
        return self.key_exchange.get_public_identity()

    def initiate_session(self, remote_identity: DeviceIdentity) -> str:
        """Initiate a new session with a remote device."""
        try:
            # Perform key exchange
            key_exchange, shared_secret = self.key_exchange.initiate_key_exchange(
                remote_identity
            )

            # Store pending key exchange
            self.pending_key_exchanges[remote_identity.device_id] = (
                key_exchange,
                shared_secret,
            )

            # Serialize key exchange for transmission
            return json.dumps(key_exchange.to_dict())

        except Exception as e:
            raise PQ3Error(f"Session initiation failed: {e}") from e

    def handle_key_exchange(self, key_exchange_data: str) -> Optional[str]:
        """Handle incoming key exchange and optionally return response."""
        try:
            # Parse key exchange
            key_exchange = InitialKeyExchange.from_dict(json.loads(key_exchange_data))

            sender_id = key_exchange.sender_identity.device_id

            # Check if this is a response to our initiation
            if sender_id in self.pending_key_exchanges:
                # Complete the session establishment
                _, shared_secret = self.pending_key_exchanges[sender_id]
                session = PQ3Session(
                    self.device_id, sender_id, shared_secret, is_initiator=True
                )
                self.sessions[sender_id] = session
                del self.pending_key_exchanges[sender_id]
                return None

            # This is a new key exchange initiation
            response, shared_secret = self.key_exchange.respond_to_key_exchange(
                key_exchange
            )

            # Create session
            session = PQ3Session(
                self.device_id, sender_id, shared_secret, is_initiator=False
            )
            self.sessions[sender_id] = session

            # Return response
            return json.dumps(response.to_dict())

        except Exception as e:
            raise PQ3Error(f"Key exchange handling failed: {e}") from e

    def send_message(self, recipient_device_id: str, message: str) -> str:
        """Send a message to a recipient device."""
        if recipient_device_id not in self.sessions:
            raise ProtocolStateError(f"No session with device {recipient_device_id}")

        session = self.sessions[recipient_device_id]
        encrypted_message = session.encrypt_message(message)

        return json.dumps(encrypted_message.to_dict())

    def receive_message(self, message_data: str) -> Tuple[str, str]:
        """Receive and decrypt a message, returning (sender_id, message)."""
        try:
            # Parse message
            message = PQ3Message.from_dict(json.loads(message_data))

            sender_id = message.sender_device_id
            if sender_id not in self.sessions:
                raise ProtocolStateError(f"No session with device {sender_id}")

            session = self.sessions[sender_id]
            plaintext = session.decrypt_message(message)

            return sender_id, plaintext

        except Exception as e:
            raise PQ3Error(f"Message reception failed: {e}") from e

    def get_session_list(self) -> List[str]:
        """Get list of active session device IDs."""
        return list(self.sessions.keys())

    def get_session_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific session."""
        if device_id in self.sessions:
            return self.sessions[device_id].get_session_info()
        return None

    def close_session(self, device_id: str) -> None:
        """Close a session with a device."""
        if device_id in self.sessions:
            del self.sessions[device_id]
        if device_id in self.pending_key_exchanges:
            del self.pending_key_exchanges[device_id]

    def export_identity(self) -> str:
        """Export device identity for sharing."""
        return self.key_exchange.serialize_identity()

    @staticmethod
    def import_identity(identity_data: str) -> DeviceIdentity:
        """Import a device identity from exported data."""
        return PQ3KeyExchange.deserialize_identity(identity_data)
