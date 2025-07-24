#!/usr/bin/env python3
"""
Basic usage example for PyPQ3.

This example demonstrates how to:
1. Create two PQ3 protocol instances (Alice and Bob)
2. Exchange device identities
3. Establish a secure session
4. Send encrypted messages back and forth
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pypq3 import PQ3Protocol


def main():
    print("PyPQ3 Basic Usage Example")
    print("=" * 40)
    
    # Create two protocol instances
    print("1. Creating protocol instances for Alice and Bob...")
    alice = PQ3Protocol("alice_device_001")
    bob = PQ3Protocol("bob_device_002")
    
    # Get device identities
    alice_identity = alice.get_device_identity()
    bob_identity = bob.get_device_identity()
    
    print(f"Alice device ID: {alice_identity.device_id}")
    print(f"Bob device ID: {bob_identity.device_id}")
    
    # Alice initiates session with Bob
    print("\n2. Alice initiating session with Bob...")
    key_exchange_data = alice.initiate_session(bob_identity)
    print(f"Key exchange data size: {len(key_exchange_data)} bytes")
    
    # Bob handles the key exchange and responds
    print("\n3. Bob handling key exchange...")
    response_data = bob.handle_key_exchange(key_exchange_data)
    
    if response_data:
        print("Bob sending response to Alice...")
        alice.handle_key_exchange(response_data)
    
    # Check that sessions are established
    alice_sessions = alice.get_session_list()
    bob_sessions = bob.get_session_list()
    
    print(f"\nAlice active sessions: {alice_sessions}")
    print(f"Bob active sessions: {bob_sessions}")
    
    if not alice_sessions or not bob_sessions:
        print("ERROR: Sessions not established properly!")
        return
    
    # Send messages back and forth
    print("\n4. Sending encrypted messages...")
    
    # Alice sends message to Bob
    message1 = "Hello Bob! This is a secure PQ3 message from Alice."
    encrypted_msg1 = alice.send_message("bob_device_002", message1)
    print(f"Alice -> Bob: Message encrypted ({len(encrypted_msg1)} bytes)")
    
    # Bob receives and decrypts
    sender_id, decrypted_msg1 = bob.receive_message(encrypted_msg1)
    print(f"Bob received from {sender_id}: '{decrypted_msg1}'")
    
    # Bob responds to Alice
    message2 = "Hi Alice! PQ3 encryption is working perfectly!"
    encrypted_msg2 = bob.send_message("alice_device_001", message2)
    print(f"Bob -> Alice: Message encrypted ({len(encrypted_msg2)} bytes)")
    
    # Alice receives and decrypts
    sender_id, decrypted_msg2 = alice.receive_message(encrypted_msg2)
    print(f"Alice received from {sender_id}: '{decrypted_msg2}'")
    
    # Send a few more messages to test ratcheting
    print("\n5. Testing message ratcheting...")
    
    for i in range(3):
        msg = f"Test message #{i+1} from Alice"
        encrypted = alice.send_message("bob_device_002", msg)
        sender, decrypted = bob.receive_message(encrypted)
        print(f"Message {i+1}: '{decrypted}'")
    
    # Display session information
    print("\n6. Session information:")
    alice_session_info = alice.get_session_info("bob_device_002")
    bob_session_info = bob.get_session_info("alice_device_001")
    
    print(f"Alice session info: {alice_session_info}")
    print(f"Bob session info: {bob_session_info}")
    
    print("\nPQ3 demonstration completed successfully!")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()