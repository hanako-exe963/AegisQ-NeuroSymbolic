from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
# Generate an ECC private key
private_key = ec.generate_private_key(ec.SECP256R1())

# Derive the public key
public_key = private_key.public_key()

# ECDSA digital signature
signature = private_key.sign(
    b"important message",
    ec.ECDSA(hashes.SHA256())
)

# ECDSA signature verification
public_key.verify(
    signature,
    b"important message",
    ec.ECDSA(hashes.SHA256())
)

# ECDH key exchange scheme
exchange_algorithm = ec.ECDH()
