import hashlib
import random

# DSA parameters
L = 1024  # Bit length of p
N = 160   # Bit length of q

# Select p and q
p = random.randint(2**(L-1)+1, 2**L)  # Prime modulus p
q = random.randint(2**(N-1)+1, 2**N)  # Prime divisor q
while pow(p % q, (q-1), q) != 1:
    p = random.randint(2**(L-1)+1, 2**L)
    q = random.randint(2**(N-1)+1, 2**N)

# Private key
x = random.randint(1, q-1)

# Public key
g = pow(random.randint(2, p-2), (p-1)//q, p)
y = pow(g, x, p)

# Hash function
def sha1_hash(message):
    return int(hashlib.sha1(message.encode()).hexdigest(), 16)

# Signature generation
def generate_dsa_signature(message, p, q, g, x):
    h = sha1_hash(message)
    z = h % q
    k = 26
    r = pow(g, k, p) % q
    k_inv = pow(k, -1, q)
    s = (k_inv * (z + x * r)) % q
    return r, z, s

# Signature verification
def verify_dsa_signature(message, signature, p, q, g, y):
    r, z, s = signature
    if not (0 < r < q) or not (0 < s < q):
        return False
    h = sha1_hash(message)
    w = pow(s, -1, q)
    u1 = (z * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r

# Check the correctness of k and k^(-1)
k = 26
k_inv = pow(k, -1, q)


# Print DSA parameters
print("DSA parameters:")
print("p and q:")
print("  p:", p)
print("  q:", q)
print("g:", g)
print("Private key x:", x)
print("k:", k)
print("Public key:")
print("  y:", y)

# Print Selection of parameter sizes and hash functions for DSA
print("Selection of parameter sizes and hash functions for DSA:")
print("L:", L)
print("N:", N)
print("Correctness Check: k * k^(-1) mod q =", (k * k_inv) % q)
# Example usage
message = "Hello, world!"
signature = generate_dsa_signature(message, p, q, g, x)
r, z, s = signature
print("DSA signature generation:")
print("r:", r)
print("z:", z)
print("s:", s)

valid = verify_dsa_signature(message, signature, p, q, g, y)
print("DSA signature verification and validation:")
print("w:", pow(s, -1, q))
print("z:", z)
print("u1:", (z * pow(s, -1, q)) % q)
print("u2:", (r * pow(s, -1, q)) % q)
print("v:", (pow(g, (z * pow(s, -1, q)) % q, p) * pow(y, (r * pow(s, -1, q)) % q, p) % p) % q)
valid = verify_dsa_signature(message, signature, p, q, g, y)
if valid:
    print("Signature Verification: Valid")
else:
    print("Signature Verification: Invalid")
