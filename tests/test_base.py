"""General test of wizard.py"""

import os
import sys
import logging
import inspect
from unittest import TestCase
from subprocess import PIPE, Popen as popen

class TestWizardBaseLine(TestCase):
    """Wizard baseline tests"""
    def test_entrypoints(self):
        """Test wizard entry points"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        exit_status = os.system('wizard --test')
        assert exit_status == 0
        exit_status = os.system('wizard -t')
        assert exit_status == 0

    def test_usage_information(self):
        """Test wizard --help via direct subprocess call"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)
        output = popen(['wizard', '--help'], stdout=PIPE).communicate()[0]
        self.assertTrue('usage:' in str(output))
       
    def test_encryption(self):
        """Test wizard encryption class"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

        #SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
        #sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, '/../lib')))
        from ../lib/encrypt import Encryption

        # make sure keyfile does not exist
        tmpfile = "/tmp/keyfile.tmp"
        if os.path.isfile(tmpfile):
            try:
                os.remove(tmpfile)
            except:
                self.assertTrue(False)

        encryption = Encryption(tmpfile)
        original_string = "This is a test string"
        encrypted_string = encryption.encrypt_password(original_string)
        unencrypted_string = encryption.decrypt_password(encrypted_string)
        self.assertTrue(unencrypted_string == original_string)
        
