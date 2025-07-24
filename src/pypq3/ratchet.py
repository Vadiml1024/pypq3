"""
Double ratchet implementation with post-quantum extensions for PQ3.
"""

from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .crypto import KeyPair, SharedSecret, PQ3Crypto
from .exceptions import ProtocolStateError, CryptographicError


@dataclass
class RatchetState:
    """State for the double ratchet mechanism."""

    root_key: bytes
    chain_key_send: bytes
    chain_key_recv: bytes
    header_key: bytes
    next_header_key: bytes
    send_count: int = 0
    recv_count: int = 0
    prev_count: int = 0
    skipped_keys: Dict[Tuple[bytes, int], bytes] = None
    dh_keypair: Optional[KeyPair] = None
    dh_remote_public: Optional[bytes] = None
    kyber_counter: int = 0

    def __post_init__(self):
        if self.skipped_keys is None:
            self.skipped_keys = {}


class PQ3Ratchet:
    """Double ratchet with post-quantum extensions for PQ3."""

    MAX_SKIP = 1000
    KYBER_REKEY_INTERVAL = 50

    def __init__(self, initial_shared_secret: SharedSecret, is_alice: bool = True):
        self.is_alice = is_alice
        self.state = self._initialize_state(initial_shared_secret)

    def _initialize_state(self, shared_secret: SharedSecret) -> RatchetState:
        """Initialize ratchet state from shared secret."""
        # Derive initial keys using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=96,  # 32 bytes each for root, chain, and header keys
            salt=None,
            info=b"PQ3-ratchet-init",
            backend=default_backend(),
        )
        key_material = hkdf.derive(shared_secret.secret)

        root_key = key_material[:32]
        chain_key = key_material[32:64]
        header_key = key_material[64:96]

        # Generate initial DH keypair
        dh_keypair = KeyPair.generate()

        return RatchetState(
            root_key=root_key,
            chain_key_send=chain_key if self.is_alice else b"",
            chain_key_recv=b"" if self.is_alice else chain_key,
            header_key=header_key,
            next_header_key=header_key,
            dh_keypair=dh_keypair,
        )

    def _kdf_rk(self, root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """Key derivation function for root key and chain key."""
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=64,
            salt=root_key,
            info=b"PQ3-ratchet-rk",
            backend=default_backend(),
        )
        key_material = hkdf.derive(dh_output)
        return key_material[:32], key_material[32:64]

    def _kdf_ck(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """Key derivation function for chain key and message key."""
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=64,
            salt=chain_key,
            info=b"PQ3-ratchet-ck",
            backend=default_backend(),
        )
        key_material = hkdf.derive(b"\\x01")
        next_chain_key = key_material[:32]
        message_key = key_material[32:64]
        return next_chain_key, message_key

    def _dh_ratchet(self, remote_public_key: bytes) -> None:
        """Perform DH ratchet step."""
        try:
            # Perform ECC key exchange with remote public key
            from cryptography.hazmat.primitives.asymmetric import ec

            remote_ecc_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), remote_public_key
            )
            ecc_shared = self.state.dh_keypair.ecc_private_key.exchange(
                ec.ECDH(), remote_ecc_key
            )

            # Update root key and chain keys
            self.state.root_key, self.state.chain_key_recv = self._kdf_rk(
                self.state.root_key, ecc_shared
            )

            self.state.prev_count = self.state.send_count
            self.state.send_count = 0
            self.state.recv_count = 0

            # Generate new keypair for next ratchet
            self.state.dh_keypair = KeyPair.generate()
            self.state.dh_remote_public = remote_public_key

            # Update root key and send chain key with new keypair
            new_remote_ecc_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), remote_public_key
            )
            new_ecc_shared = self.state.dh_keypair.ecc_private_key.exchange(
                ec.ECDH(), new_remote_ecc_key
            )

            self.state.root_key, self.state.chain_key_send = self._kdf_rk(
                self.state.root_key, new_ecc_shared
            )

        except Exception as e:
            raise ProtocolStateError(f"DH ratchet failed: {e}") from e

    def _kyber_ratchet(self, kyber_ciphertext: bytes) -> None:
        """Perform post-quantum Kyber ratchet step."""
        if self.state.kyber_counter % self.KYBER_REKEY_INTERVAL == 0:
            try:
                # Decrypt Kyber ciphertext
                if not hasattr(self.state.dh_keypair, "kyber_private_key"):
                    raise ProtocolStateError("No Kyber private key available")

                import kyber_py.kyber as kyber

                kyber_shared = kyber.Kyber1024.decaps(
                    self.state.dh_keypair.kyber_private_key, kyber_ciphertext
                )

                # Mix Kyber shared secret into root key
                self.state.root_key, _ = self._kdf_rk(self.state.root_key, kyber_shared)

                self.state.kyber_counter += 1

            except Exception as e:
                raise ProtocolStateError(f"Kyber ratchet failed: {e}") from e

    def encrypt_message(
        self, plaintext: bytes, associated_data: bytes = b""
    ) -> Tuple[bytes, bytes]:
        """Encrypt a message and return ciphertext with header."""
        try:
            # Derive message key from send chain
            self.state.chain_key_send, message_key = self._kdf_ck(
                self.state.chain_key_send
            )

            # Create message header
            header = self._create_header()

            # Encrypt message
            ciphertext = PQ3Crypto.encrypt_message(
                message_key, plaintext, associated_data + header
            )

            self.state.send_count += 1

            return header, ciphertext

        except Exception as e:
            raise CryptographicError(f"Message encryption failed: {e}") from e

    def decrypt_message(
        self, header: bytes, ciphertext: bytes, associated_data: bytes = b""
    ) -> bytes:
        """Decrypt a message given header and ciphertext."""
        try:
            # Parse header to get remote public key and message number
            remote_public_key, message_number = self._parse_header(header)

            # Check if we need to perform DH ratchet
            if (
                self.state.dh_remote_public is None
                or remote_public_key != self.state.dh_remote_public
            ):
                self._skip_message_keys(self.state.recv_count)
                self._dh_ratchet(remote_public_key)

            # Skip message keys if necessary
            self._skip_message_keys(message_number)

            # Derive message key
            self.state.chain_key_recv, message_key = self._kdf_ck(
                self.state.chain_key_recv
            )

            # Decrypt message
            plaintext = PQ3Crypto.decrypt_message(
                message_key, ciphertext, associated_data + header
            )

            self.state.recv_count += 1

            return plaintext

        except Exception as e:
            raise CryptographicError(f"Message decryption failed: {e}") from e

    def _create_header(self) -> bytes:
        """Create message header with public key and counter."""
        public_key_bytes = self.state.dh_keypair.get_ecc_public_bytes()
        counter_bytes = self.state.send_count.to_bytes(4, "big")
        return public_key_bytes + counter_bytes

    def _parse_header(self, header: bytes) -> Tuple[bytes, int]:
        """Parse message header to extract public key and counter."""
        if len(header) < 69:  # 65 bytes for public key + 4 for counter
            raise ProtocolStateError("Invalid header length")

        public_key = header[:65]
        counter = int.from_bytes(header[65:69], "big")
        return public_key, counter

    def _skip_message_keys(self, until: int) -> None:
        """Skip message keys up to the given counter."""
        if self.state.recv_count + self.MAX_SKIP < until:
            raise ProtocolStateError("Too many skipped messages")

        if self.state.chain_key_recv:
            while self.state.recv_count < until:
                self.state.chain_key_recv, message_key = self._kdf_ck(
                    self.state.chain_key_recv
                )
                self.state.skipped_keys[
                    (self.state.dh_remote_public, self.state.recv_count)
                ] = message_key
                self.state.recv_count += 1

    def get_public_key(self) -> bytes:
        """Get current public key for key exchange."""
        return self.state.dh_keypair.get_ecc_public_bytes()

    def get_kyber_public_key(self) -> bytes:
        """Get current Kyber public key."""
        return self.state.dh_keypair.get_kyber_public_bytes()
