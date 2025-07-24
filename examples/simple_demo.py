#!/usr/bin/env python3
"""
Simplified PQ3 demonstration focusing on core cryptographic functionality.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import kyber_py.kyber as kyber
from pypq3.crypto import KeyPair, PQ3Crypto, SharedSecret


def simple_key_exchange_demo():
    """Demonstrate basic hybrid key exchange."""
    print("Simple PQ3 Key Exchange Demo")
    print("=" * 40)
    
    # Alice generates her keypair
    print("1. Alice generates her keypair...")
    alice_keypair = KeyPair.generate()
    alice_ecc_public = alice_keypair.get_ecc_public_bytes()
    alice_kyber_public = alice_keypair.get_kyber_public_bytes()
    print(f"Alice ECC public key: {len(alice_ecc_public)} bytes")
    print(f"Alice Kyber public key: {len(alice_kyber_public)} bytes")
    
    # Bob generates his keypair
    print("\n2. Bob generates his keypair...")
    bob_keypair = KeyPair.generate()
    bob_ecc_public = bob_keypair.get_ecc_public_bytes()
    bob_kyber_public = bob_keypair.get_kyber_public_bytes()
    print(f"Bob ECC public key: {len(bob_ecc_public)} bytes")
    print(f"Bob Kyber public key: {len(bob_kyber_public)} bytes")
    
    # Alice initiates key exchange with Bob
    print("\n3. Alice initiates key exchange with Bob...")
    alice_shared, kyber_ciphertext = PQ3Crypto.perform_key_exchange_initiator(
        alice_keypair, bob_ecc_public, bob_kyber_public
    )
    print(f"Alice computed shared secret: {len(alice_shared.secret)} bytes")
    print(f"Kyber ciphertext: {len(kyber_ciphertext)} bytes")
    
    # Bob responds to key exchange
    print("\n4. Bob responds to key exchange...")
    bob_shared = PQ3Crypto.perform_key_exchange_responder(
        bob_keypair, alice_ecc_public, kyber_ciphertext
    )
    print(f"Bob computed shared secret: {len(bob_shared.secret)} bytes")
    
    # Verify they have the same shared secret
    print("\n5. Verifying shared secrets match...")
    if alice_shared.secret == bob_shared.secret:
        print("✅ Success! Alice and Bob have the same shared secret")
    else:
        print("❌ Error! Shared secrets don't match")
        return
    
    # Demonstrate message encryption/decryption
    print("\n6. Testing message encryption...")
    message_key = PQ3Crypto.derive_message_key(alice_shared, b"test-context")
    
    plaintext = b"Hello from Alice! This is a post-quantum secure message."
    encrypted = PQ3Crypto.encrypt_message(message_key, plaintext)
    decrypted = PQ3Crypto.decrypt_message(message_key, encrypted)
    
    print(f"Original message: {plaintext.decode()}")
    print(f"Encrypted size: {len(encrypted)} bytes")
    print(f"Decrypted message: {decrypted.decode()}")
    
    if plaintext == decrypted:
        print("✅ Message encryption/decryption successful!")
    else:
        print("❌ Message encryption/decryption failed!")
    
    print("\n🎉 PQ3 cryptographic demo completed successfully!")


if __name__ == "__main__":
    try:
        simple_key_exchange_demo()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()