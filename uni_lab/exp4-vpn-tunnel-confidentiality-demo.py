"""
Experiment 4: VPN Tunnel Encryption Confidentiality Demonstration
Demonstrates data protection in transit using symmetric stream encryption.
"""

def xor_stream_cipher(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt_vpn_tunnel(plaintext: str, secret_key: str) -> bytes:
    return xor_stream_cipher(plaintext.encode('utf-8'), secret_key.encode('utf-8'))

def decrypt_vpn_tunnel(ciphertext: bytes, secret_key: str) -> str:
    return xor_stream_cipher(ciphertext, secret_key.encode('utf-8')).decode('utf-8', errors='replace')

# Test Cases
def test_exp4():
    key = "SecureVPNTunnelSecretKey2026"
    secret_payload = "PAYLOAD: Transfer $100,000 to Account 55432 - CONFIDENTIAL"
    encrypted_traffic = encrypt_vpn_tunnel(secret_payload, key)

    assert encrypted_traffic != secret_payload.encode()
    assert b"Transfer" not in encrypted_traffic
    assert b"CONFIDENTIAL" not in encrypted_traffic

    decrypted = decrypt_vpn_tunnel(encrypted_traffic, key)
    assert decrypted == secret_payload

    bad_decrypted = decrypt_vpn_tunnel(encrypted_traffic, "WrongKey")
    assert bad_decrypted != secret_payload
    print("Experiment 4: All test cases passed.")

if __name__ == "__main__":
    key = "MyVPNKey"
    msg = "Confidential Banking Record"
    cipher = encrypt_vpn_tunnel(msg, key)
    print("Encrypted in transit:", cipher)
    print("Decrypted by receiver:", decrypt_vpn_tunnel(cipher, key))
    test_exp4()
