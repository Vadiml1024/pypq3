"""
Tests for core PQ3 protocol implementation.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import json
import pytest
from unittest.mock import MagicMock, patch

from pypq3.core import PQ3Protocol, PQ3Session, PQ3Message
from pypq3.crypto import SharedSecret
from pypq3.exceptions import PQ3Error, ProtocolStateError


class TestPQ3Message:
    def test_message_serialization(self):
        """Test PQ3Message serialization and deserialization."""
        message = PQ3Message(
            sender_device_id="alice",
            recipient_device_id="bob",
            header=b"test_header",
            ciphertext=b"test_ciphertext",
            timestamp=1234567890,
            message_id="msg_001",
        )

        # Serialize
        data = message.to_dict()

        # Deserialize
        restored_message = PQ3Message.from_dict(data)

        assert restored_message.sender_device_id == message.sender_device_id
        assert restored_message.recipient_device_id == message.recipient_device_id
        assert restored_message.header == message.header
        assert restored_message.ciphertext == message.ciphertext
        assert restored_message.timestamp == message.timestamp
        assert restored_message.message_id == message.message_id


class TestPQ3Session:
    @patch("pypq3.core.PQ3Ratchet")
    def test_session_creation(self, mock_ratchet_class):
        """Test PQ3Session creation."""
        mock_ratchet = MagicMock()
        mock_ratchet_class.return_value = mock_ratchet

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret, True)

        assert session.local_device_id == "alice"
        assert session.remote_device_id == "bob"
        assert session.is_initiator is True
        assert session.message_counter == 0
        mock_ratchet_class.assert_called_once_with(shared_secret, True)

    @patch("pypq3.core.PQ3Ratchet")
    @patch("pypq3.core.time.time")
    def test_encrypt_message(self, mock_time, mock_ratchet_class):
        """Test message encryption."""
        mock_time.return_value = 1234567890
        mock_ratchet = MagicMock()
        mock_ratchet.encrypt_message.return_value = (b"header", b"ciphertext")
        mock_ratchet_class.return_value = mock_ratchet

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret)

        message = session.encrypt_message("Hello Bob!")

        assert isinstance(message, PQ3Message)
        assert message.sender_device_id == "alice"
        assert message.recipient_device_id == "bob"
        assert message.header == b"header"
        assert message.ciphertext == b"ciphertext"
        assert message.timestamp == 1234567890
        assert session.message_counter == 1

    @patch("pypq3.core.PQ3Ratchet")
    def test_decrypt_message_success(self, mock_ratchet_class):
        """Test successful message decryption."""
        mock_ratchet = MagicMock()
        mock_ratchet.decrypt_message.return_value = b"Hello Alice!"
        mock_ratchet_class.return_value = mock_ratchet

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret)

        message = PQ3Message(
            sender_device_id="bob",
            recipient_device_id="alice",
            header=b"header",
            ciphertext=b"ciphertext",
            timestamp=1234567890,
            message_id="msg_001",
        )

        plaintext = session.decrypt_message(message)
        assert plaintext == "Hello Alice!"

    @patch("pypq3.core.PQ3Ratchet")
    def test_decrypt_message_wrong_recipient(self, mock_ratchet_class):
        """Test decryption with wrong recipient."""
        mock_ratchet_class.return_value = MagicMock()

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret)

        message = PQ3Message(
            sender_device_id="bob",
            recipient_device_id="charlie",  # Wrong recipient
            header=b"header",
            ciphertext=b"ciphertext",
            timestamp=1234567890,
            message_id="msg_001",
        )

        with pytest.raises(PQ3Error, match="Message not intended for this device"):
            session.decrypt_message(message)

    @patch("pypq3.core.PQ3Ratchet")
    def test_decrypt_message_wrong_sender(self, mock_ratchet_class):
        """Test decryption with wrong sender."""
        mock_ratchet_class.return_value = MagicMock()

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret)

        message = PQ3Message(
            sender_device_id="charlie",  # Wrong sender
            recipient_device_id="alice",
            header=b"header",
            ciphertext=b"ciphertext",
            timestamp=1234567890,
            message_id="msg_001",
        )

        with pytest.raises(PQ3Error, match="Message from unexpected sender"):
            session.decrypt_message(message)

    @patch("pypq3.core.PQ3Ratchet")
    def test_encrypt_message_failure(self, mock_ratchet_class):
        """Test message encryption failure."""
        mock_ratchet = MagicMock()
        mock_ratchet.encrypt_message.side_effect = Exception("Encryption failed")
        mock_ratchet_class.return_value = mock_ratchet

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret)

        with pytest.raises(PQ3Error, match="Message encryption failed"):
            session.encrypt_message("Hello Bob!")

    @patch("pypq3.core.PQ3Ratchet")
    def test_decrypt_message_failure(self, mock_ratchet_class):
        """Test message decryption failure."""
        mock_ratchet = MagicMock()
        mock_ratchet.decrypt_message.side_effect = Exception("Decryption failed")
        mock_ratchet_class.return_value = mock_ratchet

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret)

        message = PQ3Message(
            sender_device_id="bob",
            recipient_device_id="alice",
            header=b"header",
            ciphertext=b"ciphertext",
            timestamp=1234567890,
            message_id="msg_001",
        )

        with pytest.raises(PQ3Error, match="Message decryption failed"):
            session.decrypt_message(message)

    @patch("pypq3.core.PQ3Ratchet")
    def test_get_session_info(self, mock_ratchet_class):
        """Test getting session information."""
        mock_ratchet_class.return_value = MagicMock()

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret, is_initiator=False)
        session.message_counter = 5

        info = session.get_session_info()

        assert info["local_device_id"] == "alice"
        assert info["remote_device_id"] == "bob"
        assert info["is_initiator"] is False
        assert info["message_counter"] == 5
        assert "last_activity" in info

    @patch("pypq3.core.PQ3Ratchet")
    def test_create_associated_data(self, mock_ratchet_class):
        """Test associated data creation."""
        mock_ratchet_class.return_value = MagicMock()

        shared_secret = SharedSecret(b"ecc", b"kyber")
        session = PQ3Session("alice", "bob", shared_secret)

        associated_data = session._create_associated_data()
        assert associated_data == b"alice:bob"


class TestPQ3Protocol:
    @patch("pypq3.core.PQ3KeyExchange")
    def test_protocol_creation(self, mock_key_exchange_class):
        """Test PQ3Protocol creation."""
        mock_key_exchange = MagicMock()
        mock_key_exchange_class.return_value = mock_key_exchange

        protocol = PQ3Protocol("test_device")

        assert protocol.device_id == "test_device"
        assert protocol.sessions == {}
        assert protocol.pending_key_exchanges == {}
        mock_key_exchange_class.assert_called_once_with("test_device")

    @patch("pypq3.core.PQ3KeyExchange")
    def test_get_device_identity(self, mock_key_exchange_class):
        """Test getting device identity."""
        mock_identity = MagicMock()
        mock_key_exchange = MagicMock()
        mock_key_exchange.get_public_identity.return_value = mock_identity
        mock_key_exchange_class.return_value = mock_key_exchange

        protocol = PQ3Protocol("test_device")
        identity = protocol.get_device_identity()

        assert identity == mock_identity

    @patch("pypq3.core.PQ3KeyExchange")
    def test_initiate_session(self, mock_key_exchange_class):
        """Test session initiation."""

        # Create mock objects
        mock_key_exchange_obj = MagicMock()
        mock_shared_secret = MagicMock()

        # Setup mock key exchange
        mock_key_exchange_obj.to_dict.return_value = {"test": "data"}
        mock_key_exchange_obj.sender_identity.device_id = "remote_device"

        mock_key_exchange = MagicMock()
        mock_key_exchange.initiate_key_exchange.return_value = (
            mock_key_exchange_obj,
            mock_shared_secret,
        )
        mock_key_exchange_class.return_value = mock_key_exchange

        # Create protocol and mock identity
        protocol = PQ3Protocol("test_device")
        remote_identity = MagicMock()
        remote_identity.device_id = "remote_device"

        # Test
        result = protocol.initiate_session(remote_identity)

        assert isinstance(result, str)
        data = json.loads(result)
        assert data == {"test": "data"}

    @patch("pypq3.core.PQ3KeyExchange")
    def test_send_message_no_session(self, mock_key_exchange_class):
        """Test sending message with no active session."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        with pytest.raises(ProtocolStateError, match="No session with device"):
            protocol.send_message("unknown_device", "Hello")

    @patch("pypq3.core.PQ3KeyExchange")
    @patch("pypq3.core.PQ3Session")
    def test_send_message_success(self, mock_session_class, mock_key_exchange_class):
        """Test successful message sending."""
        # Setup mocks
        mock_key_exchange_class.return_value = MagicMock()
        mock_message = MagicMock()
        mock_message.to_dict.return_value = {"message": "data"}
        mock_session = MagicMock()
        mock_session.encrypt_message.return_value = mock_message

        protocol = PQ3Protocol("test_device")
        protocol.sessions["recipient"] = mock_session

        result = protocol.send_message("recipient", "Hello")

        assert isinstance(result, str)
        data = json.loads(result)
        assert data == {"message": "data"}

    @patch("pypq3.core.PQ3KeyExchange")
    def test_get_session_list(self, mock_key_exchange_class):
        """Test getting session list."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        # Empty initially
        assert protocol.get_session_list() == []

        # Add mock sessions
        protocol.sessions["device1"] = MagicMock()
        protocol.sessions["device2"] = MagicMock()

        session_list = protocol.get_session_list()
        assert set(session_list) == {"device1", "device2"}

    @patch("pypq3.core.PQ3KeyExchange")
    def test_close_session(self, mock_key_exchange_class):
        """Test closing a session."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        # Add mock session and pending exchange
        protocol.sessions["device1"] = MagicMock()
        protocol.pending_key_exchanges["device1"] = MagicMock()

        protocol.close_session("device1")

        assert "device1" not in protocol.sessions
        assert "device1" not in protocol.pending_key_exchanges

    @patch("pypq3.core.PQ3KeyExchange")
    def test_export_import_identity(self, mock_key_exchange_class):
        """Test identity export and import."""
        mock_key_exchange = MagicMock()
        mock_key_exchange.serialize_identity.return_value = '{"device_id": "test"}'
        mock_key_exchange_class.return_value = mock_key_exchange
        mock_key_exchange_class.deserialize_identity.return_value = MagicMock()

        protocol = PQ3Protocol("test_device")

        # Test export
        exported = protocol.export_identity()
        assert exported == '{"device_id": "test"}'

        # Test import
        PQ3Protocol.import_identity('{"device_id": "test"}')
        mock_key_exchange_class.deserialize_identity.assert_called_once_with(
            '{"device_id": "test"}'
        )

    @patch("pypq3.core.PQ3KeyExchange")
    def test_initiate_session_failure(self, mock_key_exchange_class):
        """Test session initiation failure."""
        mock_key_exchange = MagicMock()
        mock_key_exchange.initiate_key_exchange.side_effect = Exception("Key exchange failed")
        mock_key_exchange_class.return_value = mock_key_exchange

        protocol = PQ3Protocol("test_device")
        remote_identity = MagicMock()
        remote_identity.device_id = "remote_device"

        with pytest.raises(PQ3Error, match="Session initiation failed"):
            protocol.initiate_session(remote_identity)

    @patch("pypq3.core.PQ3KeyExchange")
    @patch("pypq3.core.PQ3Session")
    def test_handle_key_exchange_new_initiation(self, mock_session_class, mock_key_exchange_class):
        """Test handling new key exchange initiation."""
        # Setup mocks
        mock_key_exchange = MagicMock()
        mock_response = MagicMock()
        mock_response.to_dict.return_value = {"response": "data"}
        mock_shared_secret = MagicMock()

        mock_key_exchange.respond_to_key_exchange.return_value = (mock_response, mock_shared_secret)
        mock_key_exchange_class.return_value = mock_key_exchange

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        protocol = PQ3Protocol("test_device")

        # Create test key exchange data
        sender_identity = MagicMock()
        sender_identity.device_id = "sender_device"
        
        initial_exchange = MagicMock()
        initial_exchange.sender_identity = sender_identity
        initial_exchange.to_dict.return_value = {"test": "data"}

        # Mock the JSON parsing
        key_exchange_data = '{"sender_identity": {"device_id": "sender_device"}, "test": "data"}'

        with patch("pypq3.core.InitialKeyExchange") as mock_initial_exchange_class:
            mock_initial_exchange_class.from_dict.return_value = initial_exchange
            
            response = protocol.handle_key_exchange(key_exchange_data)

        # Verify response
        assert response is not None
        response_data = json.loads(response)
        assert response_data == {"response": "data"}

        # Verify session was created
        assert "sender_device" in protocol.sessions
        mock_session_class.assert_called_once_with(
            "test_device", "sender_device", mock_shared_secret, is_initiator=False
        )

    @patch("pypq3.core.PQ3KeyExchange")
    @patch("pypq3.core.PQ3Session")
    def test_handle_key_exchange_response_to_pending(self, mock_session_class, mock_key_exchange_class):
        """Test handling key exchange response to pending exchange."""
        mock_key_exchange_class.return_value = MagicMock()
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        protocol = PQ3Protocol("test_device")

        # Add pending key exchange
        mock_shared_secret = MagicMock()
        protocol.pending_key_exchanges["sender_device"] = (MagicMock(), mock_shared_secret)

        # Create test response data
        sender_identity = MagicMock()
        sender_identity.device_id = "sender_device"
        
        response_exchange = MagicMock()
        response_exchange.sender_identity = sender_identity

        key_exchange_data = '{"sender_identity": {"device_id": "sender_device"}, "response": "data"}'

        with patch("pypq3.core.InitialKeyExchange") as mock_initial_exchange_class:
            mock_initial_exchange_class.from_dict.return_value = response_exchange
            
            response = protocol.handle_key_exchange(key_exchange_data)

        # Verify no response returned (completing existing exchange)
        assert response is None

        # Verify session was created as initiator
        assert "sender_device" in protocol.sessions
        assert "sender_device" not in protocol.pending_key_exchanges
        mock_session_class.assert_called_once_with(
            "test_device", "sender_device", mock_shared_secret, is_initiator=True
        )

    @patch("pypq3.core.PQ3KeyExchange")
    def test_handle_key_exchange_failure(self, mock_key_exchange_class):
        """Test key exchange handling failure."""
        mock_key_exchange = MagicMock()
        mock_key_exchange.respond_to_key_exchange.side_effect = Exception("Response failed")
        mock_key_exchange_class.return_value = mock_key_exchange

        protocol = PQ3Protocol("test_device")

        # Create test key exchange data
        key_exchange_data = '{"sender_identity": {"device_id": "sender_device"}, "test": "data"}'

        with patch("pypq3.core.InitialKeyExchange") as mock_initial_exchange_class:
            mock_initial_exchange = MagicMock()
            mock_initial_exchange.sender_identity.device_id = "sender_device"
            mock_initial_exchange_class.from_dict.return_value = mock_initial_exchange
            
            with pytest.raises(PQ3Error, match="Key exchange handling failed"):
                protocol.handle_key_exchange(key_exchange_data)

    @patch("pypq3.core.PQ3KeyExchange")
    @patch("pypq3.core.PQ3Session")
    def test_receive_message_success(self, mock_session_class, mock_key_exchange_class):
        """Test successful message reception."""
        mock_key_exchange_class.return_value = MagicMock()
        
        mock_session = MagicMock()
        mock_session.decrypt_message.return_value = "Hello World!"
        mock_session_class.return_value = mock_session

        protocol = PQ3Protocol("test_device")
        protocol.sessions["sender_device"] = mock_session

        # Create test message data
        message_data = json.dumps({
            "sender_device_id": "sender_device",
            "recipient_device_id": "test_device",
            "header": "68656164657264617461",  # "headerdata" in hex
            "ciphertext": "63697068657274657874646174616130",  # "ciphertextdata0" in hex
            "timestamp": 1234567890,
            "message_id": "msg_001"
        })

        sender_id, plaintext = protocol.receive_message(message_data)
        
        assert sender_id == "sender_device"
        assert plaintext == "Hello World!"

    @patch("pypq3.core.PQ3KeyExchange")
    def test_receive_message_no_session(self, mock_key_exchange_class):
        """Test message reception with no active session."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        message_data = json.dumps({
            "sender_device_id": "unknown_device",
            "recipient_device_id": "test_device",
            "header": "68656164657264617461", 
            "ciphertext": "63697068657274657874646174616130",
            "timestamp": 1234567890,
            "message_id": "msg_001"
        })

        with pytest.raises(PQ3Error, match="No session with device unknown_device"):
            protocol.receive_message(message_data)

    @patch("pypq3.core.PQ3KeyExchange")
    def test_receive_message_failure(self, mock_key_exchange_class):
        """Test message reception failure."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        # Test with invalid JSON
        with pytest.raises(PQ3Error, match="Message reception failed"):
            protocol.receive_message("invalid json")

    @patch("pypq3.core.PQ3KeyExchange")
    def test_get_session_info_existing(self, mock_key_exchange_class):
        """Test getting session info for existing session."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        mock_session = MagicMock()
        mock_session.get_session_info.return_value = {"info": "data"}
        protocol.sessions["existing_device"] = mock_session

        info = protocol.get_session_info("existing_device")
        assert info == {"info": "data"}

    @patch("pypq3.core.PQ3KeyExchange")
    def test_get_session_info_nonexistent(self, mock_key_exchange_class):
        """Test getting session info for non-existent session."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        info = protocol.get_session_info("nonexistent_device")
        assert info is None

    @patch("pypq3.core.PQ3KeyExchange")
    def test_close_session_partial_cleanup(self, mock_key_exchange_class):
        """Test closing session with only session (no pending exchange)."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")

        # Add only session, no pending exchange
        protocol.sessions["device1"] = MagicMock()

        protocol.close_session("device1")

        assert "device1" not in protocol.sessions
        # Should not raise error if no pending exchange exists
