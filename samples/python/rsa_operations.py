from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# RSA-PSS signature padding
signature_padding = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)

# RSA-OAEP encryption padding
encryption_padding = padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

# RSA signature operation
signature = private_key.sign(
    b"test message",
    signature_padding,
    hashes.SHA256()
)

# RSA encryption operation
ciphertext = public_key.encrypt(
    b"test message",
    encryption_padding
)
