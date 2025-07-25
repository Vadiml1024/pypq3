"""
Tests for ratchet module - Double ratchet with post-quantum extensions.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from unittest.mock import patch, MagicMock

from pypq3.ratchet import PQ3Ratchet, RatchetState
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
        mock_hkdf.derive.return_value = (
            b"derived_key_material_64_bytes_test_value_for_alice_init"
        )

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
        mock_hkdf.derive.return_value = (
            b"derived_key_material_64_bytes_test_value_for_bob_initx"
        )

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
        mock_hkdf.derive.return_value = (
            b"derived_key_material_64_bytes_test_value_constants_test"
        )

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
            b"new_root_key_32_bytes_test_val123"
            + b"new_recv_chain_32_bytes_test_val1",  # First KDF
            b"final_root_key_32_bytes_test_v123"
            + b"new_send_chain_32_bytes_test_val1",  # Second KDF
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
            mock_ec.EllipticCurvePublicKey.from_encoded_point.return_value = (
                mock_remote_key
            )

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

        # Verify new keypair generated (init + ratchet)
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
            mock_ec.EllipticCurvePublicKey.from_encoded_point.side_effect = ValueError(
                "Invalid key"
            )

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
            mock_kyber.Kyber1024.decaps.return_value = (
                b"kyber_shared_secret_32_bytes_test"
            )

            ratchet._kyber_ratchet(kyber_ciphertext)

        # Verify Kyber ratchet was executed
        mock_kyber.Kyber1024.decaps.assert_called_once_with(
            b"kyber_private_key_test_data", kyber_ciphertext
        )
        assert ratchet.state.kyber_counter == 51

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_kyber_ratchet_no_trigger_not_interval(
        self, mock_keypair_class, mock_hkdf_class
    ):
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
            mock_kyber.Kyber1024.decaps.return_value = (
                b"kyber_shared_secret_32_bytes_test"
            )

            ratchet._kyber_ratchet(kyber_ciphertext)

        # Verify root key was updated
        assert ratchet.state.root_key != original_root_key
        assert ratchet.state.root_key == b"updated_root_key_32_bytes_test12"

        # Verify KDF was called with Kyber shared secret
        mock_hkdf_kdf.derive.assert_called_once_with(
            b"kyber_shared_secret_32_bytes_test"
        )


class TestChainKeyOperations:
    """Test chain key derivation and message key generation."""

    def test_kdf_ck_chain_key_derivation(self):
        """Test chain key and message key derivation function."""
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

            # Setup HKDF for _kdf_ck call
            mock_hkdf_ck = MagicMock()
            mock_hkdf_ck.derive.return_value = (
                b"next_chain_key_32_bytes_test_v12" + b"message_key_32_bytes_test_val12"
            )

            mock_hkdf_class.side_effect = [mock_hkdf_init, mock_hkdf_ck]

            with patch("pypq3.ratchet.KeyPair"):
                ratchet = PQ3Ratchet(mock_shared_secret)

            # Test chain key derivation
            old_chain_key = b"old_chain_key_32_bytes_test_v123"

            next_chain_key, message_key = ratchet._kdf_ck(old_chain_key)

            assert next_chain_key == b"next_chain_key_32_bytes_test_v12"
            assert message_key == b"message_key_32_bytes_test_val12"

            # Verify HKDF was called correctly
            assert mock_hkdf_class.call_count == 2  # Initial + _kdf_ck call
            mock_hkdf_ck.derive.assert_called_once_with(b"\\x01")

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_sending_chain_key_advancement(self, mock_keypair_class, mock_hkdf_class):
        """Test sending chain key advancement during encryption."""
        # Setup mock HKDF for multiple calls
        mock_hkdf_instances = [MagicMock() for _ in range(3)]
        mock_hkdf_class.side_effect = mock_hkdf_instances

        mock_hkdf_instances[0].derive.return_value = (  # Initial state
            b"root_key_32_bytes_test_value1234"
            + b"send_chain_32_bytes_test_value12"
            + b"header_key_32_bytes_test_value12"
        )
        mock_hkdf_instances[1].derive.return_value = (  # First _kdf_ck
            b"new_chain_key_32_bytes_test_v123" + b"message_key_1_32_bytes_test_v12"
        )
        mock_hkdf_instances[2].derive.return_value = (  # Second _kdf_ck
            b"newer_chain_key_32_bytes_test_v12" + b"message_key_2_32_bytes_test_v12"
        )

        mock_keypair = MagicMock()
        mock_keypair.get_ecc_public_bytes.return_value = (
            b"\x04"
            + b"x_coord_32_bytes_test_val_123456"
            + b"y_coord_32_bytes_test_val_123456"
        )
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret, is_alice=True)

        # Store original chain key
        original_chain_key = ratchet.state.chain_key_send
        original_send_count = ratchet.state.send_count

        # Mock PQ3Crypto encryption
        with patch("pypq3.ratchet.PQ3Crypto") as mock_crypto:
            mock_crypto.encrypt_message.return_value = b"encrypted_data_test"

            # Encrypt first message
            header1, ciphertext1 = ratchet.encrypt_message(b"Hello")

            # Verify chain key advanced and send count incremented
            assert ratchet.state.chain_key_send != original_chain_key
            assert ratchet.state.send_count == original_send_count + 1

            # Store state after first message
            first_chain_key = ratchet.state.chain_key_send
            first_send_count = ratchet.state.send_count

            # Encrypt second message
            header2, ciphertext2 = ratchet.encrypt_message(b"World")

            # Verify chain key advanced again
            assert ratchet.state.chain_key_send != first_chain_key
            assert ratchet.state.send_count == first_send_count + 1

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_receiving_chain_key_advancement(self, mock_keypair_class, mock_hkdf_class):
        """Test receiving chain key advancement during decryption."""
        # Setup mock HKDF for multiple calls
        mock_hkdf_instances = [MagicMock() for _ in range(3)]
        mock_hkdf_class.side_effect = mock_hkdf_instances

        mock_hkdf_instances[0].derive.return_value = (  # Initial state
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )
        mock_hkdf_instances[1].derive.return_value = (  # First _kdf_ck
            b"new_recv_chain_32_bytes_test_v12" + b"message_key_1_32_bytes_test_v12"
        )

        mock_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret, is_alice=False)

        # Set up receive chain key and remote public key
        ratchet.state.chain_key_recv = b"recv_chain_32_bytes_test_value12"
        ratchet.state.dh_remote_public = (
            b"\x04"
            + b"remote_x_32_bytes_test_val_12345"
            + b"remote_y_32_bytes_test_val_12345"
        )

        # Store original state
        original_chain_key = ratchet.state.chain_key_recv
        original_recv_count = ratchet.state.recv_count

        # Create test header using the same remote public key to avoid DH ratchet
        test_header = ratchet.state.dh_remote_public + (0).to_bytes(4, "big")
        test_ciphertext = b"encrypted_test_data"

        # Mock PQ3Crypto decryption
        with patch("pypq3.ratchet.PQ3Crypto") as mock_crypto:
            mock_crypto.decrypt_message.return_value = b"decrypted_message"

            # Decrypt message
            plaintext = ratchet.decrypt_message(test_header, test_ciphertext)

            # Verify chain key advanced and receive count incremented
            assert ratchet.state.chain_key_recv != original_chain_key
            assert ratchet.state.recv_count == original_recv_count + 1
            assert plaintext == b"decrypted_message"


class TestMessageKeyManagement:
    """Test message key management and skipped message handling."""

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_skipped_message_key_storage(self, mock_keypair_class, mock_hkdf_class):
        """Test skipped message key storage and retrieval."""
        # Setup mock HKDF for multiple calls
        mock_hkdf_instances = [MagicMock() for _ in range(4)]
        mock_hkdf_class.side_effect = mock_hkdf_instances

        mock_hkdf_instances[0].derive.return_value = (  # Initial state
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )
        # Setup keys for skipped messages (counter 0, 1, 2)
        for i in range(1, 4):
            mock_hkdf_instances[i].derive.return_value = (
                f"chain_key_{i}_32_bytes_test_val12".encode()[:32]
                + f"message_key_{i}_32_bytes_test_v12".encode()[:32]
            )

        mock_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set up state for skipping
        ratchet.state.chain_key_recv = b"recv_chain_32_bytes_test_value12"
        ratchet.state.dh_remote_public = (
            b"remote_public_key_65_bytes_test_data_123456789012345678901234567890123456"
        )
        ratchet.state.recv_count = 0

        # Skip 3 messages (will generate keys for counters 0, 1, 2)
        ratchet._skip_message_keys(3)

        # Verify skipped keys were stored
        assert len(ratchet.state.skipped_keys) == 3
        assert ratchet.state.recv_count == 3

        # Verify correct keys were stored with proper identifiers
        remote_pub = ratchet.state.dh_remote_public
        assert (remote_pub, 0) in ratchet.state.skipped_keys
        assert (remote_pub, 1) in ratchet.state.skipped_keys
        assert (remote_pub, 2) in ratchet.state.skipped_keys

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_maximum_skipped_keys_limit(self, mock_keypair_class, mock_hkdf_class):
        """Test maximum skipped keys limit enforcement."""
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

        # Set up state
        ratchet.state.chain_key_recv = b"recv_chain_32_bytes_test_value12"
        ratchet.state.recv_count = 0

        # Try to skip more than MAX_SKIP (1000) messages
        with pytest.raises(ProtocolStateError, match="Too many skipped messages"):
            ratchet._skip_message_keys(1001)

        # Verify no keys were stored
        assert len(ratchet.state.skipped_keys) == 0
        assert ratchet.state.recv_count == 0

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_out_of_order_message_handling(self, mock_keypair_class, mock_hkdf_class):
        """Test handling of out-of-order messages using skipped keys."""
        # Setup extensive mocking for multiple operations
        mock_hkdf_instances = [MagicMock() for _ in range(6)]
        mock_hkdf_class.side_effect = mock_hkdf_instances

        mock_hkdf_instances[0].derive.return_value = (  # Initial state
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        mock_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set up state for out-of-order message scenario
        ratchet.state.chain_key_recv = b"recv_chain_32_bytes_test_value12"
        # Create properly formatted 65-byte public key (0x04 + nulls)
        remote_pub_key = b"\x04" + b"\x00" * 64  # 65 bytes total, with safe null bytes
        ratchet.state.dh_remote_public = remote_pub_key
        ratchet.state.recv_count = 0

        # Simulate receiving message with counter 2 (skipping 0, 1)
        # This should trigger skipping of messages 0 and 1
        test_message_key = b"message_key_for_counter_2_test12"

        # Mock the skipped key generation
        for i in range(
            1, 4
        ):  # Will be called for counters 0, 1, and the current message
            mock_hkdf_instances[
                i
            ].derive.return_value = f"chain_key_{i}_32_bytes_test_val12".encode()[
                :32
            ] + (
                test_message_key
                if i == 3
                else f"skipped_key_{i-1}_32_bytes_test_v12".encode()[:32]
            )

        # Create header for message with counter 2
        test_header = remote_pub_key + (2).to_bytes(4, "big")
        test_ciphertext = b"encrypted_message_counter_2"

        with (
            patch("pypq3.ratchet.PQ3Crypto") as mock_crypto,
            patch.object(ratchet, "_dh_ratchet"),
        ):
            mock_crypto.decrypt_message.return_value = b"decrypted_message_2"

            # Decrypt the out-of-order message
            plaintext = ratchet.decrypt_message(test_header, test_ciphertext)

        # Verify message was decrypted
        assert plaintext == b"decrypted_message_2"

        # Verify skipped keys were stored for messages 0 and 1
        assert len(ratchet.state.skipped_keys) == 2
        assert (remote_pub_key, 0) in ratchet.state.skipped_keys
        assert (remote_pub_key, 1) in ratchet.state.skipped_keys

        # Verify receive counter advanced to 3 (after processing message 2)
        assert ratchet.state.recv_count == 3

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_header_creation_and_parsing(self, mock_keypair_class, mock_hkdf_class):
        """Test message header creation and parsing."""
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        mock_keypair = MagicMock()
        test_public_key = (
            b"\x04"
            + b"x_coordinate_32_bytes_test_value"
            + b"y_coordinate_32_bytes_test_value"
        )
        mock_keypair.get_ecc_public_bytes.return_value = test_public_key
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set send counter
        ratchet.state.send_count = 42

        # Create header
        header = ratchet._create_header()

        # Verify header format (65 bytes public key + 4 bytes counter)
        assert len(header) == 69
        assert header[:65] == test_public_key
        assert header[65:69] == (42).to_bytes(4, "big")

        # Test header parsing
        parsed_pub_key, parsed_counter = ratchet._parse_header(header)
        assert parsed_pub_key == test_public_key
        assert parsed_counter == 42

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_header_parsing_invalid_length(self, mock_keypair_class, mock_hkdf_class):
        """Test header parsing with invalid length."""
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

        # Test with header too short
        short_header = b"too_short"
        with pytest.raises(ProtocolStateError, match="Invalid header length"):
            ratchet._parse_header(short_header)

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_encrypt_message_crypto_error(self, mock_keypair_class, mock_hkdf_class):
        """Test encrypt_message exception handling."""
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

        # Mock PQ3Crypto to raise exception
        with patch("pypq3.ratchet.PQ3Crypto") as mock_crypto:
            mock_crypto.encrypt_message.side_effect = Exception("Encryption failed")

            with pytest.raises(CryptographicError, match="Message encryption failed"):
                ratchet.encrypt_message(b"test message")

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_decrypt_message_crypto_error(self, mock_keypair_class, mock_hkdf_class):
        """Test decrypt_message exception handling."""
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

        # Create a valid header
        test_public_key = b"\x04" + b"x" * 32 + b"y" * 32
        test_header = test_public_key + (0).to_bytes(4, "big")

        # Mock PQ3Crypto to raise exception during decryption
        with patch("pypq3.ratchet.PQ3Crypto") as mock_crypto:
            mock_crypto.decrypt_message.side_effect = Exception("Decryption failed")

            with pytest.raises(CryptographicError, match="Message decryption failed"):
                ratchet.decrypt_message(test_header, b"ciphertext")

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_decrypt_message_with_dh_ratchet_needed(
        self, mock_keypair_class, mock_hkdf_class
    ):
        """Test decrypt_message when DH ratchet is needed."""
        # Setup multiple HKDF instances for the various operations
        mock_hkdf_instances = [MagicMock() for _ in range(4)]
        mock_hkdf_class.side_effect = mock_hkdf_instances

        mock_hkdf_instances[0].derive.return_value = (  # Initial state
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        mock_keypair = MagicMock()
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Set up state with no remote public key (will trigger DH ratchet)
        ratchet.state.dh_remote_public = None
        ratchet.state.recv_count = 0

        # Create header with new public key - use proper 65-byte format
        new_public_key = (
            b"\x04" + b"a" * 32 + b"b" * 32
        )  # 65 bytes: 0x04 + 32-byte x + 32-byte y
        test_header = new_public_key + (0).to_bytes(4, "big")

        # Mock _skip_message_keys and _dh_ratchet
        with (
            patch.object(ratchet, "_skip_message_keys") as mock_skip,
            patch.object(ratchet, "_dh_ratchet") as mock_dh_ratchet,
            patch("pypq3.ratchet.PQ3Crypto") as mock_crypto,
        ):
            # Setup return values
            mock_crypto.decrypt_message.return_value = b"decrypted"

            # Mock the _kdf_ck call
            mock_hkdf_instances[1].derive.return_value = (
                b"new_chain_32_bytes_test_value12" + b"message_key_32_bytes_test_val12"
            )

            # Decrypt message
            result = ratchet.decrypt_message(test_header, b"ciphertext")

            # Verify DH ratchet was triggered
            mock_skip.assert_called_with(0)  # Skip to current recv_count
            mock_dh_ratchet.assert_called_once_with(new_public_key)
            assert result == b"decrypted"

    @patch("pypq3.ratchet.HKDF")
    @patch("pypq3.ratchet.KeyPair")
    def test_get_public_key_methods(self, mock_keypair_class, mock_hkdf_class):
        """Test get_public_key and get_kyber_public_key methods."""
        mock_hkdf = MagicMock()
        mock_hkdf_class.return_value = mock_hkdf
        mock_hkdf.derive.return_value = (
            b"root_key_32_bytes_test_value1234"
            + b"chain_key_32_bytes_test_value123"
            + b"header_key_32_bytes_test_value12"
        )

        mock_keypair = MagicMock()
        mock_keypair.get_ecc_public_bytes.return_value = b"ecc_public_key_test"
        mock_keypair.get_kyber_public_bytes.return_value = b"kyber_public_key_test"
        mock_keypair_class.generate.return_value = mock_keypair

        mock_shared_secret = MagicMock()
        mock_shared_secret.secret = b"shared_secret_32_bytes_test123"
        ratchet = PQ3Ratchet(mock_shared_secret)

        # Test get_public_key
        ecc_key = ratchet.get_public_key()
        assert ecc_key == b"ecc_public_key_test"
        mock_keypair.get_ecc_public_bytes.assert_called_once()

        # Test get_kyber_public_key
        kyber_key = ratchet.get_kyber_public_key()
        assert kyber_key == b"kyber_public_key_test"
        mock_keypair.get_kyber_public_bytes.assert_called_once()
