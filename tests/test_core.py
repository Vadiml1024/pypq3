"""
Tests for core PQ3 protocol implementation.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pypq3.core import PQ3Protocol, PQ3Session, PQ3Message
from pypq3.protocol import DeviceIdentity
from pypq3.crypto import SharedSecret
from pypq3.exceptions import PQ3Error, ProtocolStateError, MessageDecodeError


class TestPQ3Message:
    
    def test_message_serialization(self):
        """Test PQ3Message serialization and deserialization."""
        message = PQ3Message(
            sender_device_id="alice",
            recipient_device_id="bob",
            header=b"test_header",
            ciphertext=b"test_ciphertext",
            timestamp=1234567890,
            message_id="msg_001"
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
    
    @patch('pypq3.core.PQ3Ratchet')
    def test_session_creation(self, mock_ratchet_class):
        """Test PQ3Session creation."""
        mock_ratchet = MagicMock()
        mock_ratchet_class.return_value = mock_ratchet
        
        shared_secret = SharedSecret(b'ecc', b'kyber')
        session = PQ3Session("alice", "bob", shared_secret, True)
        
        assert session.local_device_id == "alice"
        assert session.remote_device_id == "bob"
        assert session.is_initiator is True
        assert session.message_counter == 0
        mock_ratchet_class.assert_called_once_with(shared_secret, True)
    
    @patch('pypq3.core.PQ3Ratchet')
    @patch('pypq3.core.time.time')
    def test_encrypt_message(self, mock_time, mock_ratchet_class):
        """Test message encryption."""
        mock_time.return_value = 1234567890
        mock_ratchet = MagicMock()
        mock_ratchet.encrypt_message.return_value = (b'header', b'ciphertext')
        mock_ratchet_class.return_value = mock_ratchet
        
        shared_secret = SharedSecret(b'ecc', b'kyber')
        session = PQ3Session("alice", "bob", shared_secret)
        
        message = session.encrypt_message("Hello Bob!")
        
        assert isinstance(message, PQ3Message)
        assert message.sender_device_id == "alice"
        assert message.recipient_device_id == "bob"
        assert message.header == b'header'
        assert message.ciphertext == b'ciphertext'
        assert message.timestamp == 1234567890
        assert session.message_counter == 1
    
    @patch('pypq3.core.PQ3Ratchet')
    def test_decrypt_message_success(self, mock_ratchet_class):
        """Test successful message decryption."""
        mock_ratchet = MagicMock()
        mock_ratchet.decrypt_message.return_value = b'Hello Alice!'
        mock_ratchet_class.return_value = mock_ratchet
        
        shared_secret = SharedSecret(b'ecc', b'kyber')
        session = PQ3Session("alice", "bob", shared_secret)
        
        message = PQ3Message(
            sender_device_id="bob",
            recipient_device_id="alice",
            header=b'header',
            ciphertext=b'ciphertext',
            timestamp=1234567890,
            message_id="msg_001"
        )
        
        plaintext = session.decrypt_message(message)
        assert plaintext == "Hello Alice!"
    
    @patch('pypq3.core.PQ3Ratchet')
    def test_decrypt_message_wrong_recipient(self, mock_ratchet_class):
        """Test decryption with wrong recipient."""
        mock_ratchet_class.return_value = MagicMock()
        
        shared_secret = SharedSecret(b'ecc', b'kyber')
        session = PQ3Session("alice", "bob", shared_secret)
        
        message = PQ3Message(
            sender_device_id="bob",
            recipient_device_id="charlie",  # Wrong recipient
            header=b'header',
            ciphertext=b'ciphertext',
            timestamp=1234567890,
            message_id="msg_001"
        )
        
        with pytest.raises(PQ3Error, match="Message not intended for this device"):
            session.decrypt_message(message)


class TestPQ3Protocol:
    
    @patch('pypq3.core.PQ3KeyExchange')
    def test_protocol_creation(self, mock_key_exchange_class):
        """Test PQ3Protocol creation."""
        mock_key_exchange = MagicMock()
        mock_key_exchange_class.return_value = mock_key_exchange
        
        protocol = PQ3Protocol("test_device")
        
        assert protocol.device_id == "test_device"
        assert protocol.sessions == {}
        assert protocol.pending_key_exchanges == {}
        mock_key_exchange_class.assert_called_once_with("test_device")
    
    @patch('pypq3.core.PQ3KeyExchange')
    def test_get_device_identity(self, mock_key_exchange_class):
        """Test getting device identity."""
        mock_identity = MagicMock()
        mock_key_exchange = MagicMock()
        mock_key_exchange.get_public_identity.return_value = mock_identity
        mock_key_exchange_class.return_value = mock_key_exchange
        
        protocol = PQ3Protocol("test_device")
        identity = protocol.get_device_identity()
        
        assert identity == mock_identity
    
    @patch('pypq3.core.PQ3KeyExchange')
    def test_initiate_session(self, mock_key_exchange_class):
        """Test session initiation."""
        from pypq3.protocol import InitialKeyExchange, DeviceIdentity
        
        # Create mock objects
        mock_key_exchange_obj = MagicMock()
        mock_key_exchange_data = MagicMock()
        mock_shared_secret = MagicMock()
        
        # Setup mock key exchange
        mock_key_exchange_obj.to_dict.return_value = {"test": "data"}
        mock_key_exchange_obj.sender_identity.device_id = "remote_device"
        
        mock_key_exchange = MagicMock()
        mock_key_exchange.initiate_key_exchange.return_value = (
            mock_key_exchange_obj, mock_shared_secret
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
    
    @patch('pypq3.core.PQ3KeyExchange')
    def test_send_message_no_session(self, mock_key_exchange_class):
        """Test sending message with no active session."""
        mock_key_exchange_class.return_value = MagicMock()
        protocol = PQ3Protocol("test_device")
        
        with pytest.raises(ProtocolStateError, match="No session with device"):
            protocol.send_message("unknown_device", "Hello")
    
    @patch('pypq3.core.PQ3KeyExchange')
    @patch('pypq3.core.PQ3Session')
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
    
    @patch('pypq3.core.PQ3KeyExchange')
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
    
    @patch('pypq3.core.PQ3KeyExchange')
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
    
    @patch('pypq3.core.PQ3KeyExchange')
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
        imported = PQ3Protocol.import_identity('{"device_id": "test"}')
        mock_key_exchange_class.deserialize_identity.assert_called_once_with('{"device_id": "test"}')