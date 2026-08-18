def xor_cipher(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encrypt_tunnel(plaintext: str, key: str) -> bytes:
    return xor_cipher(plaintext.encode(), key.encode())


def decrypt_tunnel(ciphertext: bytes, key: str) -> str:
    return xor_cipher(ciphertext, key.encode()).decode(errors="replace")


# Test Cases
def test_experiment28():
    key = "VPN-Shared-Secret-Key"
    plaintext = "Transfer $50,000 to account 998211 - confidential"
    ciphertext = encrypt_tunnel(plaintext, key)

    assert ciphertext != plaintext.encode()
    assert (
        b"Transfer" not in ciphertext
    ), "Sensitive plaintext must not be visible in captured tunnel data"

    recovered = decrypt_tunnel(ciphertext, key)
    assert recovered == plaintext

    wrong_recovered = decrypt_tunnel(ciphertext, "Wrong-Key")
    assert wrong_recovered != plaintext
    print("Experiment 28: All test cases passed.")


test_experiment28()
