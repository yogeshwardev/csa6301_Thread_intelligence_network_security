import hashlib

# Simulate a stolen password hash (a real system would never expose this!)
stolen_hash = hashlib.sha256("letmein".encode()).hexdigest()

wordlist = ["123456", "password", "admin", "letmein", "qwerty"]

print("Attempting dictionary attack on stolen hash...")
for word in wordlist:
    guess_hash = hashlib.sha256(word.encode()).hexdigest()
    if guess_hash == stolen_hash:
        print(f"Password cracked: '{word}'")
        break
else:
    print("Password not found in wordlist.")
