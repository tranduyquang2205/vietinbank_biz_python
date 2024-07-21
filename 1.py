from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

# Public key in PEM format
public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz1zqQHtHvKczHh58ePiRNgOyi
HEx6lZDPlvwBTaHmkNlQyyJ06SIlMU1pmGKxILjT7n06nxG7LlFVUN5MkW/jwF39
/+drkHM5B0kh+hPQygFjRq81yxvLwolt+Vq7h+CTU0Z1wkFABcTeQQldZkJlTpyx
0c3+jq0o47wIFjq5fwIDAQAB
-----END PUBLIC KEY-----
"""

# Load the public key
public_key = serialization.load_pem_public_key(public_key_pem.encode())

def encrypt_message(message):
    # Encrypt the message using the public key
    encrypted = public_key.encrypt(
        message.encode(),
        padding.PKCS1v15()  # Padding scheme must match the one used in JavaScript
    )
    # Encode the encrypted message in base64 for readability
    encrypted_base64 = base64.b64encode(encrypted).decode()
    return encrypted_base64

# Example usage
message = "your message here"
encrypted_message = encrypt_message(message)
print("Encrypted message:", encrypted_message)
