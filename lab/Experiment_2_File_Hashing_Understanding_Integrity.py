import hashlib


def file_hash(filename, algo="sha256"):
    h = hashlib.new(algo)
    with open(filename, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


with open("sample.txt", "w") as f:
    f.write("Confidential report v1")
print("Original hash :", file_hash("sample.txt"))

with open("sample.txt", "a") as f:
    f.write(" - tampered!")
print("Modified hash :", file_hash("sample.txt"))
print("Integrity check: FAILED (hash changed) -> file was modified")
