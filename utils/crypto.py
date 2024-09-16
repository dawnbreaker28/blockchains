import hashlib
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def generate_keys():
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return signing_key.encode(encoder=HexEncoder).decode('utf-8'), \
           verify_key.encode(encoder=HexEncoder).decode('utf-8')

def sign_message(message: bytes, private_key_hex: str) -> str:
    signing_key = SigningKey(private_key_hex, encoder=HexEncoder)
    signed = signing_key.sign(message)
    return signed.signature.hex()

def verify_signature(message: bytes, signature_hex: str, public_key_hex: str) -> bool:
    verify_key = VerifyKey(public_key_hex, encoder=HexEncoder)
    signature = bytes.fromhex(signature_hex)
    try:
        verify_key.verify(message, signature)
        return True
    except Exception:
        return False
