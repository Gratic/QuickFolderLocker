import argparse
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("password", help="The password that will lock the data.", type=str)
    args = parser.parse_args()

    password = str.encode(args.password)

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    with open('salt.locker', 'wb') as saltFile:
        saltFile.write(salt)

    token = f.encrypt(b"Secret message!")
    print(token)