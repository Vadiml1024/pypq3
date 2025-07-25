"""
Tests for crypto module.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from unittest.mock import patch

from pypq3.crypto import KeyPair, SharedSecret, PQ3Crypto
from pypq3.exceptions import CryptographicError


class TestKeyPair:
    @patch("pypq3.crypto.kyber")
    def test_key_pair_generation(self, mock_kyber):
        """Test key pair generation."""
        mock_kyber.Kyber1024.keygen.return_value = (b"public_key", b"private_key")

        keypair = KeyPair.generate()

        assert keypair.ecc_private_key is not None
        assert keypair.ecc_public_key is not None
        assert keypair.kyber_public_key == b"public_key"
        assert keypair.kyber_private_key == b"private_key"

    def test_key_pair_generation_no_kyber(self):
        """Test key pair generation when Kyber is not available."""
        with patch("pypq3.crypto.kyber", None):
            with pytest.raises(CryptographicError, match="Kyber library not available"):
                KeyPair.generate()

    @patch("pypq3.crypto.kyber")
    def test_get_public_bytes(self, mock_kyber):
        """Test getting public key bytes."""
        mock_kyber.Kyber1024.keygen.return_value = (b"kyber_pub", b"kyber_priv")

        keypair = KeyPair.generate()
        ecc_bytes = keypair.get_ecc_public_bytes()
        kyber_bytes = keypair.get_kyber_public_bytes()

        assert isinstance(ecc_bytes, bytes)
        assert len(ecc_bytes) > 0
        assert kyber_bytes == b"kyber_pub"


class TestSharedSecret:
    def test_shared_secret_creation(self):
        """Test shared secret creation and combination."""
        ecc_shared = b"ecc_shared_secret"
        kyber_shared = b"kyber_shared_secret"

        secret = SharedSecret(ecc_shared, kyber_shared)

        assert secret.ecc_shared == ecc_shared
        assert secret.kyber_shared == kyber_shared
        assert isinstance(secret.secret, bytes)
        assert len(secret.secret) == 32  # HKDF output length


class TestPQ3Crypto:
    def test_derive_message_key(self):
        """Test message key derivation."""
        shared_secret = SharedSecret(b"ecc_test", b"kyber_test")

        key1 = PQ3Crypto.derive_message_key(shared_secret)
        key2 = PQ3Crypto.derive_message_key(shared_secret, b"context")

        assert isinstance(key1, bytes)
        assert isinstance(key2, bytes)
        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2  # Different contexts should produce different keys

    def test_encrypt_decrypt_message(self):
        """Test message encryption and decryption."""
        key = PQ3Crypto.secure_random(32)
        plaintext = b"Hello, PQ3 world!"
        additional_data = b"test_context"

        # Encrypt
        encrypted = PQ3Crypto.encrypt_message(key, plaintext, additional_data)

        # Decrypt
        decrypted = PQ3Crypto.decrypt_message(key, encrypted, additional_data)

        assert decrypted == plaintext

    def test_encrypt_decrypt_without_additional_data(self):
        """Test encryption/decryption without additional data."""
        key = PQ3Crypto.secure_random(32)
        plaintext = b"Test message"

        encrypted = PQ3Crypto.encrypt_message(key, plaintext)
        decrypted = PQ3Crypto.decrypt_message(key, encrypted)

        assert decrypted == plaintext

    def test_decrypt_invalid_data(self):
        """Test decryption with invalid data."""
        key = PQ3Crypto.secure_random(32)

        with pytest.raises(CryptographicError, match="Invalid encrypted data length"):
            PQ3Crypto.decrypt_message(key, b"short")

    def test_hash_data(self):
        """Test data hashing."""
        data = b"test data"
        hash1 = PQ3Crypto.hash_data(data)
        hash2 = PQ3Crypto.hash_data(data)
        hash3 = PQ3Crypto.hash_data(b"different data")

        assert isinstance(hash1, bytes)
        assert len(hash1) == 48  # SHA-384 output length
        assert hash1 == hash2  # Same input produces same hash
        assert hash1 != hash3  # Different input produces different hash

    def test_secure_random(self):
        """Test secure random generation."""
        random1 = PQ3Crypto.secure_random(16)
        random2 = PQ3Crypto.secure_random(16)
        random3 = PQ3Crypto.secure_random(32)

        assert isinstance(random1, bytes)
        assert len(random1) == 16
        assert len(random2) == 16
        assert len(random3) == 32
        assert random1 != random2  # Should be different

    @patch("pypq3.crypto.kyber")
    def test_key_exchange_success(self, mock_kyber):
        """Test successful key exchange."""
        # Setup mocks
        mock_kyber.Kyber1024.keygen.return_value = (b"pub1", b"priv1")
        mock_kyber.Kyber1024.encaps.return_value = (b"kyber_shared", b"ciphertext")

        local_keypair = KeyPair.generate()

        # Create remote keypair (will use same mock)
        remote_keypair = KeyPair.generate()

        remote_ecc_public = remote_keypair.get_ecc_public_bytes()
        remote_kyber_public = remote_keypair.get_kyber_public_bytes()

        # Perform key exchange as initiator
        shared_secret, ciphertext = PQ3Crypto.perform_key_exchange_initiator(
            local_keypair, remote_ecc_public, remote_kyber_public
        )

        assert isinstance(shared_secret, SharedSecret)
        assert isinstance(shared_secret.secret, bytes)
        assert isinstance(ciphertext, bytes)

    def test_key_exchange_no_kyber(self):
        """Test key exchange when Kyber is not available."""
        with patch("pypq3.crypto.kyber", None):
            # This will fail during KeyPair.generate(), so we test the error path
            with pytest.raises(CryptographicError, match="Kyber library not available"):
                KeyPair.generate()

    def test_kyber_import_error_coverage(self):
        """Test coverage of kyber import error handling."""
        # This test ensures the import error lines are covered
        # The actual import happens at module load time, so we test the None case
        import pypq3.crypto as crypto_module

        # Save original kyber
        original_kyber = crypto_module.kyber

        try:
            # Simulate kyber being None (import failed)
            crypto_module.kyber = None

            # Test KeyPair.generate fails
            with pytest.raises(CryptographicError, match="Kyber library not available"):
                KeyPair.generate()

        finally:
            # Restore original kyber
            crypto_module.kyber = original_kyber

    @patch("pypq3.crypto.kyber", None)
    def test_key_exchange_initiator_no_kyber(self):
        """Test key exchange initiator when kyber is None."""
        # Create a valid keypair first with kyber available
        with patch("pypq3.crypto.kyber") as mock_kyber:
            mock_kyber.Kyber1024.keygen.return_value = (b"pub", b"priv")
            keypair = KeyPair.generate()

        # Now test with kyber = None, but we need valid ECC key to reach kyber check
        valid_ecc_key = keypair.get_ecc_public_bytes()

        with pytest.raises(CryptographicError, match="Kyber library not available"):
            PQ3Crypto.perform_key_exchange_initiator(
                keypair, valid_ecc_key, b"kyber_key"
            )

    @patch("pypq3.crypto.kyber", None)
    def test_key_exchange_responder_no_kyber(self):
        """Test key exchange responder when kyber is None."""
        # Create a valid keypair first with kyber available
        with patch("pypq3.crypto.kyber") as mock_kyber:
            mock_kyber.Kyber1024.keygen.return_value = (b"pub", b"priv")
            keypair = KeyPair.generate()

        # Now test with kyber = None, but we need valid ECC key to reach kyber check
        valid_ecc_key = keypair.get_ecc_public_bytes()

        with pytest.raises(CryptographicError, match="Kyber library not available"):
            PQ3Crypto.perform_key_exchange_responder(
                keypair, valid_ecc_key, b"kyber_ciphertext"
            )

    @patch("pypq3.crypto.kyber")
    def test_key_exchange_initiator_crypto_error(self, mock_kyber):
        """Test key exchange initiator with cryptographic errors."""
        # Setup kyber mock for key generation
        mock_kyber.Kyber1024.keygen.return_value = (b"pub_key", b"priv_key")

        # Generate keypair first
        mock_keypair = KeyPair.generate()

        # Mock kyber to raise an exception during encaps
        mock_kyber.Kyber1024.encaps.side_effect = Exception("Kyber encaps failed")

        with pytest.raises(CryptographicError, match="Key exchange failed"):
            PQ3Crypto.perform_key_exchange_initiator(
                mock_keypair, b"remote_ecc_key", b"remote_kyber_key"
            )

    @patch("pypq3.crypto.kyber")
    def test_key_exchange_responder_invalid_ecc_key(self, mock_kyber):
        """Test key exchange responder with invalid ECC key."""
        # Setup kyber mock for key generation
        mock_kyber.Kyber1024.keygen.return_value = (b"pub_key", b"priv_key")

        mock_keypair = KeyPair.generate()

        # Invalid ECC key bytes that will cause parsing to fail
        invalid_ecc_key = b"invalid_ecc_key_data"

        with pytest.raises(CryptographicError, match="Key exchange failed"):
            PQ3Crypto.perform_key_exchange_responder(
                mock_keypair, invalid_ecc_key, b"kyber_ciphertext"
            )

    @patch("pypq3.crypto.kyber")
    def test_key_exchange_responder_kyber_decaps_error(self, mock_kyber):
        """Test key exchange responder with Kyber decaps error."""
        # Setup kyber mock for key generation
        mock_kyber.Kyber1024.keygen.return_value = (b"pub_key", b"priv_key")

        mock_keypair = KeyPair.generate()

        # Mock valid ECC key but kyber decaps failure
        mock_kyber.Kyber1024.decaps.side_effect = Exception("Decaps failed")

        # Use a valid ECC key format
        valid_ecc_key = mock_keypair.get_ecc_public_bytes()

        with pytest.raises(CryptographicError, match="Key exchange failed"):
            PQ3Crypto.perform_key_exchange_responder(
                mock_keypair, valid_ecc_key, b"invalid_kyber_ciphertext"
            )

    @patch("pypq3.crypto.kyber")
    def test_key_exchange_responder_success(self, mock_kyber):
        """Test successful key exchange responder path."""
        # Setup kyber mock for key generation
        mock_kyber.Kyber1024.keygen.return_value = (b"pub_key", b"priv_key")

        # Generate keypair
        keypair = KeyPair.generate()

        # Mock successful decaps
        mock_kyber.Kyber1024.decaps.return_value = b"kyber_shared_secret"

        # Use valid ECC key
        valid_ecc_key = keypair.get_ecc_public_bytes()

        # Should succeed and return SharedSecret
        result = PQ3Crypto.perform_key_exchange_responder(
            keypair, valid_ecc_key, b"kyber_ciphertext"
        )

        assert isinstance(result, SharedSecret)
        mock_kyber.Kyber1024.decaps.assert_called_once_with(
            b"priv_key", b"kyber_ciphertext"
        )

    def test_encrypt_message_invalid_key(self):
        """Test encrypt message with invalid key causing ChaCha20 error."""
        # Invalid key length (ChaCha20 needs 32 bytes)
        invalid_key = b"short_key"

        with pytest.raises(CryptographicError, match="Encryption failed"):
            PQ3Crypto.encrypt_message(invalid_key, b"plaintext")
