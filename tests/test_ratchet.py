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


class TestDHRatchetOperations:
    """Test DH ratchet operations and key rotation."""

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_dh_ratchet_step_success(self, mock_keypair_class, mock_hkdf_class):
        """Test successful DH ratchet step execution."""
        # Setup mock HKDF for initial state
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        initial_key_material = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )
        mock_hkdf.derive.side_effect = [
            initial_key_material,  # Initial state
            b"new_root_key_32_bytes_test_val123" + b"new_recv_chain_32_bytes_test_val1",  # First KDF
            b"final_root_key_32_bytes_test_v123" + b"new_send_chain_32_bytes_test_val1",  # Second KDF
        ]

        # Setup mock keypair for initial state
        mock_initial_keypair = MagicMock()
        mock_initial_keypair.ecc_private_key.exchange.side_effect = [
            b"shared_secret_1_32_bytes_test123",
            b"shared_secret_2_32_bytes_test123",
        ]

        # Setup mock keypair for new generation
        mock_new_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_new_keypair

        # Create ratchet and set up initial state
        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)
        
        # Set up DH keypair in state
        ratchet.state.dh_keypair = mock_initial_keypair
        ratchet.state.send_count = 5
        ratchet.state.recv_count = 3

        # Test remote public key
        remote_pub_key = (
            b"\x04"  # Uncompressed point prefix
            + b"x_coordinate_32_bytes_test_value_for_remote_public_key123"
            + b"y_coordinate_32_bytes_test_value_for_remote_public_key123"
        )

        # Execute DH ratchet step
        with patch("cryptography.hazmat.primitives.asymmetric.ec") as mock_ec:
            mock_remote_key = MagicMock()
            mock_ec.EllipticCurvePublicKey.from_encoded_point.return_value = mock_remote_key
            
            ratchet._dh_ratchet(remote_pub_key)

        # Verify state changes
        assert ratchet.state.prev_count == 5  # Previous send_count
        assert ratchet.state.send_count == 0  # Reset
        assert ratchet.state.recv_count == 0  # Reset
        assert ratchet.state.dh_keypair == mock_new_keypair  # New keypair generated
        assert ratchet.state.dh_remote_public == remote_pub_key

        # Verify initial keypair key exchange happened once  
        assert mock_initial_keypair.ecc_private_key.exchange.call_count == 1
        
        # Verify new keypair key exchange happened once
        assert mock_new_keypair.ecc_private_key.exchange.call_count == 1
        
        # Verify new keypair was generated (called once during init + once during ratchet)
        assert mock_keypair_class.generate.call_count == 2

    @patch("pypq3.ratchet.HKDF")
    def test_dh_ratchet_invalid_public_key(self, mock_hkdf_class):
        """Test DH ratchet with invalid/malformed remote public key."""
        # Setup mock HKDF for initial state
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)
        
        # Set up DH keypair in state
        mock_keypair = MagicMock()
        ratchet.state.dh_keypair = mock_keypair

        # Test with invalid public key
        invalid_pub_key = b"invalid_key_too_short"

        with patch("cryptography.hazmat.primitives.asymmetric.ec") as mock_ec:
            # Simulate invalid key error
            mock_ec.EllipticCurvePublicKey.from_encoded_point.side_effect = ValueError("Invalid key")
            
            with pytest.raises(ProtocolStateError, match="DH ratchet failed"):
                ratchet._dh_ratchet(invalid_pub_key)

    @patch("pypq3.ratchet.HKDF")
    def test_dh_ratchet_no_keypair(self, mock_hkdf_class):
        """Test DH ratchet fails when no DH keypair is available."""
        # Setup mock HKDF for initial state
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)
        
        # Set up DH keypair to None (override default initialization)
        ratchet.state.dh_keypair = None

        remote_pub_key = (
            b"\x04"
            + b"x_coordinate_32_bytes_test_value_for_remote_public_key123"
            + b"y_coordinate_32_bytes_test_value_for_remote_public_key123"
        )

        with pytest.raises(ProtocolStateError, match="DH ratchet failed"):
            ratchet._dh_ratchet(remote_pub_key)

    def test_kdf_rk_key_derivation(self):
        """Test root key and chain key derivation function."""
        # Create ratchet without extensive mocking to test _kdf_rk directly
        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        
        with patch("pypq3.ratchet.HKDF") as mock_hkdf_class:
            # Setup initial HKDF for ratchet creation
            mock_hkdf_init = MagicMock()
            mock_hkdf_init.derive.return_value = (
                b"root_key_32_bytes_test_value1234"
                + b"chain_key_32_bytes_test_value123"
                + b"header_key_32_bytes_test_value12"
            )
            
            # Setup HKDF for _kdf_rk call
            mock_hkdf_kdf = MagicMock()
            mock_hkdf_kdf.derive.return_value = (
                b"new_root_key_32_bytes_test_val12" 
                + b"new_chain_key_32_bytes_test_va12"
            )
            
            mock_hkdf_class.side_effect = [mock_hkdf_init, mock_hkdf_kdf]
            
            with patch("pypq3.ratchet.KeyPair"):
                ratchet = PQ3Ratchet(mock_shared_secret)

            # Test key derivation
            old_root_key = b"old_root_key_32_bytes_test_val123"
            dh_output = b"dh_shared_secret_32_bytes_test123"

            new_root_key, new_chain_key = ratchet._kdf_rk(old_root_key, dh_output)

            assert new_root_key == b"new_root_key_32_bytes_test_val12"
            assert new_chain_key == b"new_chain_key_32_bytes_test_va12"

            # Verify HKDF was called correctly for key derivation
            assert mock_hkdf_class.call_count == 2  # Initial + KDF call
            mock_hkdf_kdf.derive.assert_called_once_with(dh_output)


class TestKyberRatchetIntegration:
    """Test Kyber ratchet integration and post-quantum key rotation."""

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_kyber_ratchet_trigger_interval(self, mock_keypair_class, mock_hkdf_class):
        """Test Kyber ratchet triggering at correct interval."""
        # Setup mock HKDF for initial state
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.side_effect = [
            # Initial state
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12",
            # KDF result for Kyber ratchet
            b"new_root_key_32_bytes_test_val12" + b"new_chain_key_32_bytes_test_va12",
        ]

        # Setup keypair with Kyber private key
        mock_keypair = MagicMock()
        mock_keypair.kyber_private_key = b"kyber_private_key_test_data"
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set up state to trigger Kyber ratchet (counter at multiple of 50)
        ratchet.state.kyber_counter = 50  # Should trigger
        kyber_ciphertext = b"kyber_ciphertext_test_data_for_decaps_operation"

        with patch("kyber_py.kyber") as mock_kyber:
            mock_kyber.Kyber1024.decaps.return_value = b"kyber_shared_secret_32_bytes_test"
            
            ratchet._kyber_ratchet(kyber_ciphertext)

        # Verify Kyber ratchet was executed
        mock_kyber.Kyber1024.decaps.assert_called_once_with(
            b"kyber_private_key_test_data", kyber_ciphertext
        )
        assert ratchet.state.kyber_counter == 51

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_kyber_ratchet_no_trigger_not_interval(self, mock_keypair_class, mock_hkdf_class):
        """Test Kyber ratchet not triggering when not at interval."""
        # Setup mock HKDF for initial state
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        mock_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set up state to NOT trigger Kyber ratchet (counter not at multiple of 50)
        ratchet.state.kyber_counter = 25  # Should NOT trigger
        original_counter = ratchet.state.kyber_counter
        kyber_ciphertext = b"kyber_ciphertext_test_data"

        with patch("kyber_py.kyber") as mock_kyber:
            ratchet._kyber_ratchet(kyber_ciphertext)

        # Verify Kyber ratchet was NOT executed
        mock_kyber.Kyber1024.decaps.assert_not_called()
        assert ratchet.state.kyber_counter == original_counter  # Unchanged

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_kyber_ratchet_no_private_key(self, mock_keypair_class, mock_hkdf_class):
        """Test Kyber ratchet failure when no Kyber private key available."""
        # Setup mock HKDF for initial state
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        # Setup keypair WITHOUT Kyber private key
        mock_keypair = MagicMock()
        del mock_keypair.kyber_private_key  # Remove the attribute
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set up state to trigger Kyber ratchet
        ratchet.state.kyber_counter = 100  # Should trigger
        kyber_ciphertext = b"kyber_ciphertext_test_data"

        with pytest.raises(ProtocolStateError, match="Kyber ratchet failed"):
            ratchet._kyber_ratchet(kyber_ciphertext)

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_kyber_ratchet_decaps_failure(self, mock_keypair_class, mock_hkdf_class):
        """Test Kyber ratchet failure during decapsulation."""
        # Setup mock HKDF for initial state
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        # Setup keypair with Kyber private key
        mock_keypair = MagicMock()
        mock_keypair.kyber_private_key = b"kyber_private_key_test_data"
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set up state to trigger Kyber ratchet
        ratchet.state.kyber_counter = 150  # Should trigger
        kyber_ciphertext = b"invalid_kyber_ciphertext"

        with patch("kyber_py.kyber") as mock_kyber:
            # Simulate decapsulation failure
            mock_kyber.Kyber1024.decaps.side_effect = ValueError("Invalid ciphertext")
            
            with pytest.raises(ProtocolStateError, match="Kyber ratchet failed"):
                ratchet._kyber_ratchet(kyber_ciphertext)

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_kyber_ratchet_root_key_update(self, mock_keypair_class, mock_hkdf_class):
        """Test that Kyber ratchet properly updates root key."""
        # Setup mock HKDF for initial state and KDF
        mock_hkdf_init = MagicMock()
        mock_hkdf_kdf = MagicMock()
        mock_hkdf_class.side_effect = [mock_hkdf_init, mock_hkdf_kdf]
        
        mock_hkdf_init.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )
        mock_hkdf_kdf.derive.return_value = (
            b"updated_root_key_32_bytes_test12" + b"ignored_chain_key_32_bytes_te12"
        )

        # Setup keypair with Kyber private key
        mock_keypair = MagicMock()
        mock_keypair.kyber_private_key = b"kyber_private_key_test_data"
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Store original root key for comparison
        original_root_key = ratchet.state.root_key
        
        # Set up state to trigger Kyber ratchet
        ratchet.state.kyber_counter = 200  # Should trigger
        kyber_ciphertext = b"valid_kyber_ciphertext_test_data"

        with patch("kyber_py.kyber") as mock_kyber:
            mock_kyber.Kyber1024.decaps.return_value = b"kyber_shared_secret_32_bytes_test" 
            
            ratchet._kyber_ratchet(kyber_ciphertext)

        # Verify root key was updated
        assert ratchet.state.root_key != original_root_key
        assert ratchet.state.root_key == b"updated_root_key_32_bytes_test12"
        
        # Verify KDF was called with Kyber shared secret
        mock_hkdf_kdf.derive.assert_called_once_with(b"kyber_shared_secret_32_bytes_test")