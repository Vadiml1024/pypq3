"""
Tests for PQ3 protocol key exchange implementation.
"""

import sys
import json
from unittest.mock import MagicMock, patch, call
import pytest

sys.path.insert(0, "src")

from pypq3.protocol import DeviceIdentity, InitialKeyExchange, PQ3KeyExchange
from pypq3.crypto import SharedSecret
from pypq3.exceptions import KeyExchangeError


class TestDeviceIdentity:
    """Test DeviceIdentity dataclass functionality."""

    def test_device_identity_creation(self):
        """Test basic DeviceIdentity creation."""
        device_id = "test_device_123"
        ecc_key = (
            b"ecc_public_key_65_bytes_test_data_123456789012345678901234567890123456789"
        )
        kyber_key = (
            b"kyber_public_key_test_data_1234567890123456789012345678901234567890"
        )
        signature = b"test_signature_data_12345678901234567890"

        identity = DeviceIdentity(
            device_id=device_id,
            ecc_public_key=ecc_key,
            kyber_public_key=kyber_key,
            signature=signature,
        )

        assert identity.device_id == device_id
        assert identity.ecc_public_key == ecc_key
        assert identity.kyber_public_key == kyber_key
        assert identity.signature == signature

    def test_device_identity_without_signature(self):
        """Test DeviceIdentity creation without signature."""
        device_id = "test_device_456"
        ecc_key = b"ecc_public_key_test_data"
        kyber_key = b"kyber_public_key_test_data"

        identity = DeviceIdentity(
            device_id=device_id,
            ecc_public_key=ecc_key,
            kyber_public_key=kyber_key,
        )

        assert identity.device_id == device_id
        assert identity.ecc_public_key == ecc_key
        assert identity.kyber_public_key == kyber_key
        assert identity.signature is None

    def test_device_identity_to_dict(self):
        """Test DeviceIdentity serialization to dictionary."""
        device_id = "test_device_789"
        ecc_key = b"ecc_key_data"
        kyber_key = b"kyber_key_data"
        signature = b"signature_data"

        identity = DeviceIdentity(
            device_id=device_id,
            ecc_public_key=ecc_key,
            kyber_public_key=kyber_key,
            signature=signature,
        )

        result = identity.to_dict()

        expected = {
            "device_id": device_id,
            "ecc_public_key": ecc_key.hex(),
            "kyber_public_key": kyber_key.hex(),
            "signature": signature.hex(),
        }

        assert result == expected

    def test_device_identity_to_dict_no_signature(self):
        """Test DeviceIdentity serialization without signature."""
        device_id = "test_device_no_sig"
        ecc_key = b"ecc_key_data"
        kyber_key = b"kyber_key_data"

        identity = DeviceIdentity(
            device_id=device_id,
            ecc_public_key=ecc_key,
            kyber_public_key=kyber_key,
        )

        result = identity.to_dict()

        expected = {
            "device_id": device_id,
            "ecc_public_key": ecc_key.hex(),
            "kyber_public_key": kyber_key.hex(),
            "signature": None,
        }

        assert result == expected

    def test_device_identity_from_dict(self):
        """Test DeviceIdentity deserialization from dictionary."""
        data = {
            "device_id": "test_device_from_dict",
            "ecc_public_key": "656363546573744461746131323334",  # hex
            "kyber_public_key": "6b7962657254657374446174613132333435363738",  # hex
            "signature": "7369674461746131323334",  # "sigData1234" in hex
        }

        identity = DeviceIdentity.from_dict(data)

        assert identity.device_id == "test_device_from_dict"
        assert identity.ecc_public_key == bytes.fromhex(data["ecc_public_key"])
        assert identity.kyber_public_key == bytes.fromhex(data["kyber_public_key"])
        assert identity.signature == bytes.fromhex(data["signature"])

    def test_device_identity_from_dict_no_signature(self):
        """Test DeviceIdentity deserialization without signature."""
        data = {
            "device_id": "test_device_no_sig",
            "ecc_public_key": "656363546573744461746131323334",
            "kyber_public_key": "6b7962657254657374446174613132333435363738",
            "signature": None,
        }

        identity = DeviceIdentity.from_dict(data)

        assert identity.device_id == "test_device_no_sig"
        assert identity.ecc_public_key == bytes.fromhex(data["ecc_public_key"])
        assert identity.kyber_public_key == bytes.fromhex(data["kyber_public_key"])
        assert identity.signature is None


class TestInitialKeyExchange:
    """Test InitialKeyExchange dataclass functionality."""

    def test_initial_key_exchange_creation(self):
        """Test InitialKeyExchange creation."""
        sender_identity = DeviceIdentity(
            device_id="sender_device",
            ecc_public_key=b"sender_ecc_key",
            kyber_public_key=b"sender_kyber_key",
        )
        ephemeral_ecc = b"ephemeral_ecc_public_key_data"
        kyber_ciphertext = b"kyber_ciphertext_data"
        timestamp = 1234567890

        key_exchange = InitialKeyExchange(
            sender_identity=sender_identity,
            ephemeral_ecc_public=ephemeral_ecc,
            kyber_ciphertext=kyber_ciphertext,
            timestamp=timestamp,
        )

        assert key_exchange.sender_identity == sender_identity
        assert key_exchange.ephemeral_ecc_public == ephemeral_ecc
        assert key_exchange.kyber_ciphertext == kyber_ciphertext
        assert key_exchange.timestamp == timestamp

    def test_initial_key_exchange_to_dict(self):
        """Test InitialKeyExchange serialization to dictionary."""
        sender_identity = DeviceIdentity(
            device_id="sender_test",
            ecc_public_key=b"ecc_data",
            kyber_public_key=b"kyber_data",
        )
        ephemeral_ecc = b"ephemeral_data"
        kyber_ciphertext = b"ciphertext_data"
        timestamp = 9876543210

        key_exchange = InitialKeyExchange(
            sender_identity=sender_identity,
            ephemeral_ecc_public=ephemeral_ecc,
            kyber_ciphertext=kyber_ciphertext,
            timestamp=timestamp,
        )

        result = key_exchange.to_dict()

        expected = {
            "sender_identity": sender_identity.to_dict(),
            "ephemeral_ecc_public": ephemeral_ecc.hex(),
            "kyber_ciphertext": kyber_ciphertext.hex(),
            "timestamp": timestamp,
        }

        assert result == expected

    def test_initial_key_exchange_from_dict(self):
        """Test InitialKeyExchange deserialization from dictionary."""
        sender_data = {
            "device_id": "sender_from_dict",
            "ecc_public_key": "656363446174614672616d6544696374",  # hex
            "kyber_public_key": "6b79626572446174614672616d6544696374",  # hex
            "signature": None,
        }

        data = {
            "sender_identity": sender_data,
            "ephemeral_ecc_public": "657068656d6572616c446174614672616d65",  # hex
            "kyber_ciphertext": "63697068657274657874446174614672616d65",  # hex
            "timestamp": 1122334455,
        }

        key_exchange = InitialKeyExchange.from_dict(data)

        assert key_exchange.sender_identity.device_id == "sender_from_dict"
        assert key_exchange.ephemeral_ecc_public == bytes.fromhex(
            data["ephemeral_ecc_public"]
        )
        assert key_exchange.kyber_ciphertext == bytes.fromhex(data["kyber_ciphertext"])
        assert key_exchange.timestamp == 1122334455


class TestPQ3KeyExchange:
    """Test PQ3KeyExchange class functionality."""

    @patch("pypq3.protocol.KeyPair")
    def test_pq3_key_exchange_initialization(self, mock_keypair_class):
        """Test PQ3KeyExchange initialization."""
        # Setup mocks
        mock_keypair = MagicMock()
        mock_keypair.get_ecc_public_bytes.return_value = (
            b"ecc_public_key_bytes_test_data"
        )
        mock_keypair.get_kyber_public_bytes.return_value = (
            b"kyber_public_key_bytes_test_data"
        )
        mock_keypair_class.generate.return_value = mock_keypair

        device_id = "test_device_init"

        # Create PQ3KeyExchange instance
        exchange = PQ3KeyExchange(device_id)

        # Verify initialization
        assert exchange.device_id == device_id
        assert exchange.identity_keypair == mock_keypair
        assert exchange.device_identity.device_id == device_id
        assert (
            exchange.device_identity.ecc_public_key == b"ecc_public_key_bytes_test_data"
        )
        assert (
            exchange.device_identity.kyber_public_key
            == b"kyber_public_key_bytes_test_data"
        )
        assert exchange.device_identity.signature is None

        # Verify KeyPair.generate was called once
        mock_keypair_class.generate.assert_called_once()

    @patch("pypq3.protocol.KeyPair")
    @patch("pypq3.protocol.PQ3Crypto")
    @patch("time.time")
    def test_initiate_key_exchange_success(
        self, mock_time, mock_crypto, mock_keypair_class
    ):
        """Test successful key exchange initiation."""
        # Setup mocks
        mock_time.return_value = 1234567890.5

        # Setup identity keypair
        mock_identity_keypair = MagicMock()
        mock_identity_keypair.get_ecc_public_bytes.return_value = b"identity_ecc_public"
        mock_identity_keypair.get_kyber_public_bytes.return_value = (
            b"identity_kyber_public"
        )

        # Setup ephemeral keypair
        mock_ephemeral_keypair = MagicMock()
        mock_ephemeral_keypair.get_ecc_public_bytes.return_value = (
            b"ephemeral_ecc_public"
        )

        mock_keypair_class.generate.side_effect = [
            mock_identity_keypair,
            mock_ephemeral_keypair,
        ]

        # Setup crypto mocks
        identity_shared = SharedSecret(b"identity_ecc_shared", b"identity_kyber_shared")
        ephemeral_shared = SharedSecret(
            b"ephemeral_ecc_shared", b"ephemeral_kyber_shared"
        )

        mock_crypto.perform_key_exchange_initiator.side_effect = [
            (identity_shared, b"identity_kyber_ct"),
            (ephemeral_shared, b"ephemeral_kyber_ct"),
        ]
        mock_crypto.hash_data.side_effect = [
            b"combined_ecc_hash_32_bytes_test12",
            b"combined_kyber_hash_32_bytes_te12",
        ]

        # Create remote identity
        remote_identity = DeviceIdentity(
            device_id="remote_device",
            ecc_public_key=b"remote_ecc_key",
            kyber_public_key=b"remote_kyber_key",
        )

        # Create exchange instance
        exchange = PQ3KeyExchange("initiator_device")

        # Initiate key exchange
        key_exchange_msg, combined_secret = exchange.initiate_key_exchange(
            remote_identity
        )

        # Verify key exchange message
        assert isinstance(key_exchange_msg, InitialKeyExchange)
        assert key_exchange_msg.sender_identity == exchange.device_identity
        assert key_exchange_msg.ephemeral_ecc_public == b"ephemeral_ecc_public"
        assert key_exchange_msg.kyber_ciphertext == b"ephemeral_kyber_ct"
        assert key_exchange_msg.timestamp == 1234567890

        # Verify combined secret
        assert isinstance(combined_secret, SharedSecret)
        assert combined_secret.ecc_shared == b"combined_ecc_hash_32_bytes_test12"
        assert combined_secret.kyber_shared == b"combined_kyber_hash_32_bytes_te12"

        # Verify crypto calls
        assert mock_crypto.perform_key_exchange_initiator.call_count == 2
        mock_crypto.perform_key_exchange_initiator.assert_has_calls(
            [
                call(mock_identity_keypair, b"remote_ecc_key", b"remote_kyber_key"),
                call(mock_ephemeral_keypair, b"remote_ecc_key", b"remote_kyber_key"),
            ]
        )

    @patch("pypq3.protocol.KeyPair")
    @patch("pypq3.protocol.PQ3Crypto")
    def test_initiate_key_exchange_crypto_failure(
        self, mock_crypto, mock_keypair_class
    ):
        """Test key exchange initiation with crypto failure."""
        # Setup mocks
        mock_identity_keypair = MagicMock()
        mock_ephemeral_keypair = MagicMock()
        mock_keypair_class.generate.side_effect = [
            mock_identity_keypair,
            mock_ephemeral_keypair,
        ]

        # Make crypto operation fail
        mock_crypto.perform_key_exchange_initiator.side_effect = Exception(
            "Crypto operation failed"
        )

        remote_identity = DeviceIdentity(
            device_id="remote_device",
            ecc_public_key=b"remote_ecc_key",
            kyber_public_key=b"remote_kyber_key",
        )

        exchange = PQ3KeyExchange("initiator_device")

        # Verify exception is raised and wrapped
        with pytest.raises(KeyExchangeError, match="Key exchange initiation failed"):
            exchange.initiate_key_exchange(remote_identity)

    @patch("pypq3.protocol.KeyPair")
    @patch("pypq3.protocol.PQ3Crypto")
    @patch("time.time")
    def test_respond_to_key_exchange_success(
        self, mock_time, mock_crypto, mock_keypair_class
    ):
        """Test successful key exchange response."""
        # Setup mocks
        mock_time.return_value = 2345678901.7

        # Setup identity keypair
        mock_identity_keypair = MagicMock()
        mock_identity_keypair.get_ecc_public_bytes.return_value = (
            b"responder_identity_ecc"
        )
        mock_identity_keypair.get_kyber_public_bytes.return_value = (
            b"responder_identity_kyber"
        )

        # Setup temp keypair for response
        mock_temp_keypair = MagicMock()
        mock_temp_keypair.get_ecc_public_bytes.return_value = b"temp_ecc_public"

        mock_keypair_class.generate.side_effect = [
            mock_identity_keypair,
            mock_temp_keypair,
        ]

        # Setup crypto mocks
        identity_shared = SharedSecret(
            b"response_identity_ecc_shared", b"response_identity_kyber_shared"
        )
        ephemeral_shared = SharedSecret(
            b"response_ephemeral_ecc_shared", b"response_ephemeral_kyber_shared"
        )

        mock_crypto.perform_key_exchange_initiator.return_value = (
            identity_shared,
            b"response_identity_kyber_ct",
        )
        mock_crypto.perform_key_exchange_responder.return_value = ephemeral_shared
        mock_crypto.hash_data.side_effect = [
            b"response_combined_ecc_hash_32_by12",
            b"response_combined_kyber_hash_32_12",
        ]

        # Create incoming key exchange
        sender_identity = DeviceIdentity(
            device_id="sender_device",
            ecc_public_key=b"sender_ecc_key",
            kyber_public_key=b"sender_kyber_key",
        )

        incoming_exchange = InitialKeyExchange(
            sender_identity=sender_identity,
            ephemeral_ecc_public=b"incoming_ephemeral_ecc",
            kyber_ciphertext=b"incoming_kyber_ct",
            timestamp=1111111111,
        )

        # Create responder
        responder = PQ3KeyExchange("responder_device")

        # Respond to key exchange
        response_msg, combined_secret = responder.respond_to_key_exchange(
            incoming_exchange
        )

        # Verify response message
        assert isinstance(response_msg, InitialKeyExchange)
        assert response_msg.sender_identity == responder.device_identity
        assert response_msg.ephemeral_ecc_public == b"temp_ecc_public"
        assert response_msg.kyber_ciphertext == b"response_identity_kyber_ct"
        assert response_msg.timestamp == 2345678901

        # Verify combined secret
        assert isinstance(combined_secret, SharedSecret)
        assert combined_secret.ecc_shared == b"response_combined_ecc_hash_32_by12"
        assert combined_secret.kyber_shared == b"response_combined_kyber_hash_32_12"

        # Verify crypto calls
        mock_crypto.perform_key_exchange_initiator.assert_called_once_with(
            mock_identity_keypair, b"sender_ecc_key", b"sender_kyber_key"
        )
        mock_crypto.perform_key_exchange_responder.assert_called_once_with(
            mock_identity_keypair, b"incoming_ephemeral_ecc", b"incoming_kyber_ct"
        )

    @patch("pypq3.protocol.KeyPair")
    @patch("pypq3.protocol.PQ3Crypto")
    def test_respond_to_key_exchange_failure(self, mock_crypto, mock_keypair_class):
        """Test key exchange response with failure."""
        # Setup mocks
        mock_identity_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_identity_keypair

        # Make responder crypto operation fail
        mock_crypto.perform_key_exchange_responder.side_effect = Exception(
            "Responder operation failed"
        )

        # Create incoming key exchange
        sender_identity = DeviceIdentity(
            device_id="sender_device",
            ecc_public_key=b"sender_ecc_key",
            kyber_public_key=b"sender_kyber_key",
        )

        incoming_exchange = InitialKeyExchange(
            sender_identity=sender_identity,
            ephemeral_ecc_public=b"incoming_ephemeral_ecc",
            kyber_ciphertext=b"incoming_kyber_ct",
            timestamp=1111111111,
        )

        responder = PQ3KeyExchange("responder_device")

        # Verify exception is raised and wrapped
        with pytest.raises(KeyExchangeError, match="Key exchange response failed"):
            responder.respond_to_key_exchange(incoming_exchange)

    @patch("pypq3.protocol.KeyPair")
    @patch("pypq3.protocol.PQ3Crypto")
    def test_combine_shared_secrets(self, mock_crypto, mock_keypair_class):
        """Test shared secret combination."""
        # Setup mocks
        mock_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_keypair
        mock_crypto.hash_data.side_effect = [
            b"combined_ecc_hash_result_32_byte12",
            b"combined_kyber_hash_result_32_by12",
        ]

        exchange = PQ3KeyExchange("test_device")

        # Create test shared secrets
        identity_shared = SharedSecret(b"identity_ecc_data", b"identity_kyber_data")
        ephemeral_shared = SharedSecret(b"ephemeral_ecc_data", b"ephemeral_kyber_data")

        # Combine secrets
        result = exchange._combine_shared_secrets(identity_shared, ephemeral_shared)

        # Verify result
        assert isinstance(result, SharedSecret)
        assert result.ecc_shared == b"combined_ecc_hash_result_32_byte12"
        assert result.kyber_shared == b"combined_kyber_hash_result_32_by12"

        # Verify hash_data calls
        mock_crypto.hash_data.assert_has_calls(
            [
                call(b"identity_ecc_data" + b"ephemeral_ecc_data"),
                call(b"identity_kyber_data" + b"ephemeral_kyber_data"),
            ]
        )

    @patch("pypq3.protocol.KeyPair")
    def test_serialize_identity(self, mock_keypair_class):
        """Test device identity serialization."""
        mock_keypair = MagicMock()
        mock_keypair.get_ecc_public_bytes.return_value = b"serialization_ecc_key"
        mock_keypair.get_kyber_public_bytes.return_value = b"serialization_kyber_key"
        mock_keypair_class.generate.return_value = mock_keypair

        exchange = PQ3KeyExchange("serialization_test_device")

        # Serialize identity
        result = exchange.serialize_identity()

        # Verify it's valid JSON
        data = json.loads(result)
        assert data["device_id"] == "serialization_test_device"
        assert data["ecc_public_key"] == b"serialization_ecc_key".hex()
        assert data["kyber_public_key"] == b"serialization_kyber_key".hex()
        assert data["signature"] is None

    def test_deserialize_identity(self):
        """Test device identity deserialization."""
        test_data = {
            "device_id": "deserialization_test_device",
            "ecc_public_key": "646573657269616c697a6174696f6e5f6563635f6b6579",  # hex
            "kyber_public_key": "646573657269616c697a6174696f6e5f6b796265725f6b6579",
            "signature": None,
        }

        json_data = json.dumps(test_data)

        # Deserialize identity
        result = PQ3KeyExchange.deserialize_identity(json_data)

        # Verify result
        assert isinstance(result, DeviceIdentity)
        assert result.device_id == "deserialization_test_device"
        assert result.ecc_public_key == b"deserialization_ecc_key"
        assert result.kyber_public_key == b"deserialization_kyber_key"
        assert result.signature is None

    @patch("pypq3.protocol.KeyPair")
    def test_get_public_identity(self, mock_keypair_class):
        """Test getting public identity."""
        mock_keypair = MagicMock()
        mock_keypair.get_ecc_public_bytes.return_value = b"public_identity_ecc_key"
        mock_keypair.get_kyber_public_bytes.return_value = b"public_identity_kyber_key"
        mock_keypair_class.generate.return_value = mock_keypair

        exchange = PQ3KeyExchange("public_identity_test_device")

        # Get public identity
        result = exchange.get_public_identity()

        # Verify it returns the device identity
        assert result == exchange.device_identity
        assert result.device_id == "public_identity_test_device"
        assert result.ecc_public_key == b"public_identity_ecc_key"
        assert result.kyber_public_key == b"public_identity_kyber_key"
