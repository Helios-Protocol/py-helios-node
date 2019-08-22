import getpass
import hashlib
import os
from helios.constants import SCRYPT_N, SCRYPT_P, SCRYPT_R
import json

def save_rpc_admin_password(password, file_location):
    password_bytes = bytes(password, 'utf-8')
    salt_bytes = os.urandom(32)

    password_hash = hashlib.scrypt(password=password_bytes, salt=salt_bytes, n=SCRYPT_N, r=SCRYPT_P, p=SCRYPT_R)

    # the first 32 bytes are salt, the rest is the password hash

    to_save_bytes = salt_bytes + password_hash

    f = open(file_location, 'wb')
    f.write(to_save_bytes)
    f.close()


def verify_rpc_admin_password(password, file_location):
    # the first 32 bytes are salt, the rest is the password hash
    try:
        with open(file_location, 'rb') as f:
            salt_bytes = f.read(32)
            existing_password_hash = f.read()

            test_password_bytes = bytes(password, 'utf-8')

            test_password_hash = hashlib.scrypt(password=test_password_bytes, salt=salt_bytes, n=SCRYPT_N, r=SCRYPT_P, p=SCRYPT_R)

            return test_password_hash == existing_password_hash
    except Exception:
        raise Exception("A problem occurred when verifying the password. Ensure that you have set a password by starting the node with the set-admin-rpc-password argument")

