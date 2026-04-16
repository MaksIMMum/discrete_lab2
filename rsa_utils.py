"""
RSA utilities for secure chat.
"""

import random
import hashlib
import json

def gcd(a: int, b: int) -> int:
    """Compute the greatest common divisor using the Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int):
    """Extended Euclidean algorithm. Returns (gcd, x, y)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Find d such that (e * d) % phi == 1."""
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi


def is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin algorithm"""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n) #(a**d) % n  in github repo
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 512) -> int:
    """Generate a random prime number of given bit length."""
    while True:
        n = random.randrange(2**(bits - 1) + 1, 2**bits, 2)
        if is_prime(n):
            return n


def generate_keys(bits: int = 1024):
    """
    Generate RSA key pair.
    Returns ((e, n), (d, n))  –  (public_key, private_key).
    """
    half = bits // 2
    p = generate_prime(half)
    q = generate_prime(half)
    while q == p:
        q = generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)

    return (e, n), (d, n)


def encrypt_message(message: str, public_key: tuple) -> list[int]:
    """Encrypt a string character by character: c = pow(ord(char), e, n)."""
    e, n = public_key
    return [pow(ord(char), e, n) for char in message]


def decrypt_message(encrypted: list[int], private_key: tuple) -> str:
    """Decrypt a list of integers back to a string: char = chr(pow(c, d, n))."""
    d, n = private_key
    return "".join([chr(pow(c, d, n)) for c in encrypted])


def compute_hash(message: str) -> str:
    """Compute SHA-256 hash of a text message."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def verify_hash(message: str, expected_hash: str) -> bool:
    """Verify message integrity by comparing hashes."""
    return compute_hash(message) == expected_hash


def pack_message(text: str, public_key: tuple) -> str:
    """
    Compute SHA-256 hash of the text.
    Encrypt the text with the user's public key.
    Return a JSON string:  {"hash": ..., "data": [...]}
    """
    h = compute_hash(text)
    encrypted = encrypt_message(text, public_key)
    return json.dumps({"hash": h, "data": encrypted})


def unpack_message(raw: str, private_key: tuple) -> str:
    """
    Parse JSON.
    Decrypt the message.
    Verify hash.
    Return the text if hash is valid, else raise ValueError.
    """
    obj = json.loads(raw)
    encrypted = obj["data"]
    text = decrypt_message(encrypted, private_key)
    if not verify_hash(text, obj["hash"]):
        raise ValueError("Message invalid?")
    return text
