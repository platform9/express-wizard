import os
import sys
import globals
from cryptography.fernet import Fernet

class Encryption:

    def __init__(self, keyfile):
        if not os.path.isfile(keyfile):
            # initialize keyfile
            try:
                self.key = Fernet.generate_key()
                keystore_fh = open(globals.ENCRYPTION_KEY_STORE, "w")
                keystore_fh.write("{}".format(self.key))
                keystore_fh.close()
            except:
                sys.stdout.write("FATAL: failed to initialize encryption (failed to write {})\n".format(keyfile))
                sys.exit(0)
        else:
            # read encryption key from keyfile
            try:
                keystore_fh = open(keyfile, "r")
                self.key = keystore_fh.read()
                keystore_fh.close()
            except:
                sys.stdout.write("FATAL: failed to initialize encryption (failed to read {})\n".format(keyfile))
                sys.exit(0)

    def encrypt_password(self,unencrypted_string):
        cipher_suite = Fernet(self.key)
        encrypted_string = cipher_suite.encrypt(b"{}".format(unencrypted_string))
        return(encrypted_string)


    def decrypt_password(self,unencrypted_string):
        cipher_suite = Fernet(self.key)
        plain_text = cipher_suite.decrypt(unencrypted_string)
        return(plain_text)

