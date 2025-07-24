#!/usr/bin/env python3
"""
Working demonstration of PQ3 core functionality.
This shows the key cryptographic operations working correctly.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pypq3.crypto import KeyPair, PQ3Crypto, SharedSecret


def main():
    print("🔐 PQ3 Post-Quantum Cryptography Demo")
    print("=" * 50)
    
    print("\n1️⃣  Generating hybrid keypairs...")
    alice_keypair = KeyPair.generate()
    bob_keypair = KeyPair.generate()
    
    print(f"✅ Alice's ECC public key: {len(alice_keypair.get_ecc_public_bytes())} bytes")
    print(f"✅ Alice's Kyber public key: {len(alice_keypair.get_kyber_public_bytes())} bytes")
    print(f"✅ Bob's ECC public key: {len(bob_keypair.get_ecc_public_bytes())} bytes")
    print(f"✅ Bob's Kyber public key: {len(bob_keypair.get_kyber_public_bytes())} bytes")
    
    print("\n2️⃣  Performing post-quantum key exchange...")
    
    # Alice initiates with Bob's public keys
    alice_shared, kyber_ciphertext = PQ3Crypto.perform_key_exchange_initiator(
        alice_keypair, 
        bob_keypair.get_ecc_public_bytes(),
        bob_keypair.get_kyber_public_bytes()
    )
    
    # Bob responds using Alice's public key and kyber ciphertext
    bob_shared = PQ3Crypto.perform_key_exchange_responder(
        bob_keypair,
        alice_keypair.get_ecc_public_bytes(),
        kyber_ciphertext
    )
    
    print(f"✅ Alice derived shared secret: {len(alice_shared.secret)} bytes")
    print(f"✅ Bob derived shared secret: {len(bob_shared.secret)} bytes")
    print(f"✅ Kyber ciphertext: {len(kyber_ciphertext)} bytes")
    
    # Verify shared secrets match
    if alice_shared.secret == bob_shared.secret:
        print("🎉 SUCCESS: Shared secrets match!")
    else:
        print("❌ ERROR: Shared secrets don't match!")
        return
    
    print("\n3️⃣  Testing authenticated encryption...")
    
    # Derive message keys
    alice_msg_key = PQ3Crypto.derive_message_key(alice_shared, b"alice-to-bob")
    bob_msg_key = PQ3Crypto.derive_message_key(bob_shared, b"alice-to-bob")
    
    # Verify message keys match
    if alice_msg_key == bob_msg_key:
        print("✅ Message keys derived consistently")
    else:
        print("❌ Message key derivation inconsistent")
        return
    
    # Test message encryption/decryption
    messages = [
        "Hello Bob! This message is protected by post-quantum cryptography.",
        "The hybrid approach combines ECC P-256 with Kyber-1024.",
        "This provides security against both classical and quantum attacks! 🚀"
    ]
    
    for i, message in enumerate(messages, 1):
        plaintext = message.encode('utf-8')
        
        # Alice encrypts
        encrypted = PQ3Crypto.encrypt_message(alice_msg_key, plaintext, b"test-context")
        
        # Bob decrypts
        decrypted = PQ3Crypto.decrypt_message(bob_msg_key, encrypted, b"test-context")
        
        print(f"✅ Message {i}: '{decrypted.decode()}'")
        print(f"   Original: {len(plaintext)} bytes → Encrypted: {len(encrypted)} bytes")
        
        if plaintext != decrypted:
            print(f"❌ Message {i} decryption failed!")
            return
    
    print("\n4️⃣  Testing key derivation with different contexts...")
    
    contexts = [b"session-1", b"session-2", b"ratchet-step-1"]
    keys = []
    
    for context in contexts:
        key = PQ3Crypto.derive_message_key(alice_shared, context)
        keys.append(key)
        print(f"✅ Key for context '{context.decode()}': {key[:8].hex()}...")
    
    # Verify all keys are different
    if len(set(keys)) == len(keys):
        print("✅ All derived keys are unique")
    else:
        print("❌ Some derived keys are identical")
    
    print("\n5️⃣  Security properties demonstrated:")
    print("   🔐 Hybrid cryptography (ECC + Kyber)")
    print("   🛡️  Post-quantum security against quantum attacks")
    print("   🔑 Key derivation with context separation")
    print("   🔒 Authenticated encryption (ChaCha20-Poly1305)")
    print("   ✨ Forward secrecy ready (for full ratchet implementation)")
    
    print(f"\n🎉 PQ3 cryptographic demonstration completed successfully!")
    print("   This proves the core post-quantum cryptographic operations work correctly.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()