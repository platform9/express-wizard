import os
import sys
import globals
from cryptography.fernet import Fernet

class Encryption:

    def __init__(self, keyfile):
        if not os.path.isfile(keyfile) or os.stat(keyfile).st_size == 0:
            # initialize keyfile
            try:
                os.makedirs(os.path.dirname(keyfile), exist_ok=True)
                self.key = Fernet.generate_key()
                keystore_fh = open(keyfile, "w")
                keystore_fh.write(self.key.decode('utf-8'))
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
        if type(unencrypted_string) == str:
            unencrypted_string = unencrypted_string.encode('utf-8')
        encrypted_string = cipher_suite.encrypt(unencrypted_string)
        return(encrypted_string.decode('utf-8'))


    def decrypt_password(self,encrypted_string):
        cipher_suite = Fernet(self.key)
        if type(encrypted_string) == str:
            encrypted_string = encrypted_string.encode('utf-8')
        plain_text = cipher_suite.decrypt(encrypted_string)
        return(plain_text.decode('utf-8'))

