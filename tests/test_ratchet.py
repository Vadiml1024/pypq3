"""
Tests for ratchet module - Double ratchet with post-quantum extensions.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from unittest.mock import patch, MagicMock

from pypq3.ratchet import PQ3Ratchet, RatchetState
from pypq3.crypto import SharedSecret, KeyPair
from pypq3.exceptions import ProtocolStateError, CryptographicError


class TestRatchetState:
    """Test RatchetState dataclass functionality."""

    def test_ratchet_state_initialization_defaults(self):
        """Test RatchetState initialization with default values."""
        state = RatchetState(
            root_key=b"root_key_32_bytes_test_value123",
            chain_key_send=b"send_key_32_bytes_test_value123",
            chain_key_recv=b"recv_key_32_bytes_test_value123",
            header_key=b"header_key_32_bytes_test_val123",
            next_header_key=b"next_header_32_bytes_test_val123",
        )

        assert state.root_key == b"root_key_32_bytes_test_value123"
        assert state.chain_key_send == b"send_key_32_bytes_test_value123"
        assert state.chain_key_recv == b"recv_key_32_bytes_test_value123"
        assert state.header_key == b"header_key_32_bytes_test_val123"
        assert state.next_header_key == b"next_header_32_bytes_test_val123"
        assert state.send_count == 0
        assert state.recv_count == 0
        assert state.prev_count == 0
        assert state.skipped_keys == {}
        assert state.dh_keypair is None
        assert state.dh_remote_public is None
        assert state.kyber_counter == 0

    def test_ratchet_state_initialization_custom_values(self):
        """Test RatchetState initialization with custom values."""
        mock_keypair = MagicMock()
        skipped_keys = {(b"key1", 1): b"value1"}

        state = RatchetState(
            root_key=b"root_key_32_bytes_test_value123",
            chain_key_send=b"send_key_32_bytes_test_value123",
            chain_key_recv=b"recv_key_32_bytes_test_value123",
            header_key=b"header_key_32_bytes_test_val123",
            next_header_key=b"next_header_32_bytes_test_val123",
            send_count=5,
            recv_count=3,
            prev_count=2,
            skipped_keys=skipped_keys,
            dh_keypair=mock_keypair,
            dh_remote_public=b"remote_public_key",
            kyber_counter=10,
        )

        assert state.send_count == 5
        assert state.recv_count == 3
        assert state.prev_count == 2
        assert state.skipped_keys == skipped_keys
        assert state.dh_keypair == mock_keypair
        assert state.dh_remote_public == b"remote_public_key"
        assert state.kyber_counter == 10

    def test_ratchet_state_post_init_skipped_keys(self):
        """Test __post_init__ properly initializes skipped_keys when None."""
        state = RatchetState(
            root_key=b"root_key_32_bytes_test_value123",
            chain_key_send=b"send_key_32_bytes_test_value123",
            chain_key_recv=b"recv_key_32_bytes_test_value123",
            header_key=b"header_key_32_bytes_test_val123",
            next_header_key=b"next_header_32_bytes_test_val123",
            skipped_keys=None,
        )

        assert state.skipped_keys == {}
        assert isinstance(state.skipped_keys, dict)


class TestPQ3RatchetInitialization:
    """Test PQ3Ratchet initialization and state setup."""

    @patch("pypq3.ratchet.HKDF")
    def test_ratchet_initialization_alice(self, mock_hkdf_class):
        """Test ratchet initialization as Alice (initiator)."""
        # Setup mock HKDF
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = b"derived_key_material_64_bytes_test_value_for_alice_init"

        # Create mock shared secret
        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"

        # Initialize ratchet
        ratchet = PQ3Ratchet(mock_shared_secret, is_alice=True)

        assert ratchet.is_alice is True
        assert isinstance(ratchet.state, RatchetState)

        # Verify HKDF was called for key derivation
        mock_hkdf_class.assert_called_once()
        mock_hkdf.derive.assert_called_once_with(b"shared_secret_32_bytes_test123")

    @patch("pypq3.ratchet.HKDF")
    def test_ratchet_initialization_bob(self, mock_hkdf_class):
        """Test ratchet initialization as Bob (responder)."""
        # Setup mock HKDF
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = b"derived_key_material_64_bytes_test_value_for_bob_initx"

        # Create mock shared secret
        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"

        # Initialize ratchet
        ratchet = PQ3Ratchet(mock_shared_secret, is_alice=False)

        assert ratchet.is_alice is False
        assert isinstance(ratchet.state, RatchetState)

        # Verify HKDF was called for key derivation
        mock_hkdf_class.assert_called_once()
        mock_hkdf.derive.assert_called_once_with(b"shared_secret_32_bytes_test123")

    @patch("pypq3.ratchet.HKDF")
    def test_ratchet_constants(self, mock_hkdf_class):
        """Test ratchet constants are properly set."""
        # Setup mock HKDF
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = b"derived_key_material_64_bytes_test_value_constants_test"

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"

        ratchet = PQ3Ratchet(mock_shared_secret)

        assert ratchet.MAX_SKIP == 1000
        assert ratchet.KYBER_REKEY_INTERVAL == 50

    @patch("pypq3.ratchet.HKDF")
    def test_ratchet_state_properties_after_init(self, mock_hkdf_class):
        """Test ratchet state has expected properties after initialization."""
        # Setup mock HKDF to return specific key material
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        # Return 96 bytes: 32 for root_key, 32 for chain_key, 32 for header_key
        key_material = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )
        mock_hkdf.derive.return_value = key_material

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"

        ratchet = PQ3Ratchet(mock_shared_secret)
        state = ratchet.state

        # Check that state was properly initialized
        assert isinstance(state.root_key, bytes)
        assert isinstance(state.chain_key_send, bytes)
        assert isinstance(state.chain_key_recv, bytes)
        assert isinstance(state.header_key, bytes)
        assert isinstance(state.next_header_key, bytes)
        assert state.send_count == 0
        assert state.recv_count == 0
        assert state.prev_count == 0
        assert state.skipped_keys == {}
        assert state.kyber_counter == 0