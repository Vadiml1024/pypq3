# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Development Commands

### Package Management
```bash
# Install in development mode with all dependencies
pip install -e .[dev]

# Install only runtime dependencies  
pip install -e .
```

### Testing
```bash
# Run all tests with coverage
pytest tests/ --cov=pypq3 --cov-report=term-missing

# Run specific test file
pytest tests/test_core.py -v

# Run single test method
pytest tests/test_core.py::TestPQ3Protocol::test_send_message_success -v
```

### Code Quality
```bash
# Format code (required before commits)
black src/ tests/

# Check formatting without changes
black --check src/ tests/

# Lint code (uses .flake8 config)
flake8 src/ tests/

# Type checking (may show warnings for missing stubs)
mypy src/
```

### Running Examples
```bash
# Basic usage demonstration
python examples/basic_usage.py

# Cryptographic operations demo
python examples/simple_demo.py

# Working demo with validation
python examples/working_demo.py
```

## Architecture Overview

PyPQ3 implements Apple's PQ3 post-quantum cryptographic protocol through a layered architecture:

### Core Protocol Stack
```
PQ3Protocol (main interface)
├── PQ3KeyExchange (initial handshake) 
├── PQ3Session (per-device messaging)
│   └── PQ3Ratchet (forward secrecy)
│       └── PQ3Crypto (primitives)
└── Exception hierarchy
```

### Key Components

**PQ3Protocol** (`src/pypq3/core.py`): Main protocol interface managing device identities and multiple sessions. Entry point for all high-level operations.

**PQ3KeyExchange** (`src/pypq3/protocol.py`): Handles initial hybrid key exchange combining ECC P-256 and Kyber-1024. Creates `DeviceIdentity` objects for device authentication.

**PQ3Session** (`src/pypq3/core.py`): Manages encrypted messaging between two specific devices. Each session maintains independent state and message counters.

**PQ3Ratchet** (`src/pypq3/ratchet.py`): Implements Signal-style double ratchet with post-quantum extensions. Provides forward secrecy through automatic key rotation every 50 messages.

**PQ3Crypto** (`src/pypq3/crypto.py`): Low-level cryptographic primitives including hybrid key exchange, ChaCha20-Poly1305 encryption, and HKDF key derivation.

### Cryptographic Design

- **Hybrid Security**: Combines classical ECC with post-quantum Kyber-1024
- **Forward Secrecy**: Double ratchet automatically rotates encryption keys
- **Message Authentication**: ChaCha20-Poly1305 AEAD prevents tampering
- **Key Derivation**: HKDF-SHA384 for all key material derivation

### Protocol Flow

1. **Device Identity Creation**: Each device generates hybrid ECC+Kyber keypairs
2. **Key Exchange**: Devices perform initial handshake combining both key types
3. **Session Establishment**: Shared secrets initialize double ratchet state
4. **Message Exchange**: Each message uses fresh derived keys with automatic ratcheting

### Data Serialization

All protocol messages serialize to JSON with binary data hex-encoded:
- `DeviceIdentity.to_dict()` / `from_dict()` for device public keys
- `InitialKeyExchange.to_dict()` / `from_dict()` for handshake messages  
- `PQ3Message.to_dict()` / `from_dict()` for encrypted messages

### Testing Strategy

Tests use extensive mocking to isolate components:
- **Core tests**: Protocol logic, session management, message flow
- **Crypto tests**: Cryptographic primitives, key exchange, encryption
- **Coverage**: 61% overall, with exceptions and crypto well-covered

### Error Handling

Custom exception hierarchy with specific error types:
- `PQ3Error`: Base exception for all protocol errors
- `KeyExchangeError`: Key exchange and handshake failures
- `CryptographicError`: Low-level crypto operation failures
- `ProtocolStateError`: Invalid protocol state transitions
- `MessageDecodeError`: Message parsing and validation errors

### Configuration Files

- **pyproject.toml**: Modern Python packaging with tool configurations
- **.flake8**: Linting rules (88 char line length, test file import exceptions)
- **GitHub Actions**: Automated testing on Python 3.9-3.12 with linting

### Development Notes

- **Dependencies**: Requires `cryptography`, `pycryptodome`, and `kyber-py` packages
- **Python Support**: 3.9+ with full type hints throughout codebase
- **Security Focus**: Educational implementation - see README security considerations for production use
- **Code Style**: Black formatting (88 chars), flake8 linting, mypy type checking required