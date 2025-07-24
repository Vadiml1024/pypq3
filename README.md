# PyPQ3: Python Implementation of Apple's PQ3 Protocol

PyPQ3 is a Python implementation of Apple's PQ3 (Post-Quantum 3) cryptographic protocol, designed for secure messaging with post-quantum cryptographic protection.

## Features

- **Hybrid Cryptography**: Combines traditional ECC (P-256) with post-quantum Kyber-1024
- **Double Ratchet**: Implements Signal-style double ratchet with post-quantum extensions
- **Forward Secrecy**: Provides forward secrecy and post-compromise security
- **Level 3 Security**: Achieves Apple's highest security level classification
- **Key Rotation**: Automatic key rotation every 50 messages or 7 days
- **Modern Python**: Type hints, dataclasses, and clean API design

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd pypq3

# Install in development mode
pip install -e .

# Or install dependencies manually
pip install cryptography pycryptodome kyber-py
```

## Quick Start

```python
from pypq3 import PQ3Protocol

# Create protocol instances for two devices
alice = PQ3Protocol("alice_device_001")
bob = PQ3Protocol("bob_device_002")

# Exchange device identities
alice_identity = alice.get_device_identity()
bob_identity = bob.get_device_identity()

# Alice initiates session with Bob
key_exchange_data = alice.initiate_session(bob_identity)

# Bob handles the key exchange
response_data = bob.handle_key_exchange(key_exchange_data)

# Alice completes the handshake
if response_data:
    alice.handle_key_exchange(response_data)

# Now they can exchange encrypted messages
encrypted_msg = alice.send_message("bob_device_002", "Hello Bob!")
sender_id, plaintext = bob.receive_message(encrypted_msg)
print(f"Received from {sender_id}: {plaintext}")
```

## Architecture

The implementation consists of several key components:

### Core Modules

- **`PQ3Protocol`**: Main protocol interface for managing sessions and message exchange
- **`PQ3Session`**: Manages individual encrypted sessions between devices
- **`PQ3KeyExchange`**: Handles initial key exchange and device identity management
- **`PQ3Ratchet`**: Implements the double ratchet mechanism with post-quantum extensions
- **`PQ3Crypto`**: Low-level cryptographic primitives and operations

### Cryptographic Components

- **ECC**: P-256 elliptic curve for traditional key agreement
- **Kyber-1024**: NIST-standardized post-quantum KEM
- **ChaCha20-Poly1305**: Authenticated encryption for messages
- **HKDF-SHA384**: Key derivation and entropy extraction
- **SHA-384**: Cryptographic hashing

## Security Features

### Post-Quantum Protection
- Uses Kyber-1024 for quantum-resistant key encapsulation
- Hybrid design combines classical and post-quantum cryptography
- Protects against "Harvest Now, Decrypt Later" attacks

### Forward Secrecy
- Implements Signal's double ratchet protocol
- Generates new encryption keys for each message
- Automatically deletes old keys after use

### Post-Compromise Security
- Key rotation limits impact of key compromise
- Fresh randomness injected with each ratchet step
- Separate chains for sending and receiving

## API Reference

### PQ3Protocol

```python
# Create protocol instance
protocol = PQ3Protocol(device_id: str)

# Get device identity for sharing
identity = protocol.get_device_identity() -> DeviceIdentity

# Initiate session with remote device
key_exchange_data = protocol.initiate_session(remote_identity: DeviceIdentity) -> str

# Handle incoming key exchange
response = protocol.handle_key_exchange(key_exchange_data: str) -> Optional[str]

# Send encrypted message
encrypted_msg = protocol.send_message(recipient_device_id: str, message: str) -> str

# Receive and decrypt message
sender_id, plaintext = protocol.receive_message(message_data: str) -> Tuple[str, str]

# Manage sessions
sessions = protocol.get_session_list() -> List[str]
session_info = protocol.get_session_info(device_id: str) -> Optional[Dict]
protocol.close_session(device_id: str)
```

### DeviceIdentity

```python
# Device identity contains public keys and metadata
identity = DeviceIdentity(
    device_id: str,
    ecc_public_key: bytes,
    kyber_public_key: bytes,
    signature: Optional[bytes] = None
)

# Serialization
data = identity.to_dict()
identity = DeviceIdentity.from_dict(data)
```

## Examples

See the `examples/` directory for complete usage examples:

- `basic_usage.py`: Simple two-party messaging example
- Run with: `python examples/basic_usage.py`

## Testing

Run the test suite:

```bash
# Install development dependencies
pip install -e .[dev]

# Run tests
pytest tests/

# Run with coverage
pytest --cov=pypq3 tests/
```

## Security Considerations

This implementation is for **educational and research purposes**. For production use, consider:

- **Formal Security Review**: Have the implementation reviewed by cryptographic experts
- **Side-Channel Protection**: Add protection against timing and power analysis attacks
- **Secure Key Storage**: Implement secure key storage and memory management
- **Identity Verification**: Add proper digital signature verification for device identities
- **Network Security**: Implement secure transport and authentication mechanisms

## Protocol Specifications

This implementation is based on:

- [Apple's PQ3 Technical Blog Post](https://security.apple.com/blog/imessage-pq3/)
- [Formal Analysis of PQ3](https://eprint.iacr.org/2024/1395)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Dependencies

- `cryptography>=41.0.0`: Modern cryptographic library
- `pycryptodome>=3.19.0`: Additional cryptographic primitives
- `kyber-py>=0.3.0`: Python implementation of Kyber KEM

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Disclaimer

This software is provided for educational purposes. The authors make no warranties about its fitness for production use. Users should conduct their own security analysis before using in any security-critical applications.