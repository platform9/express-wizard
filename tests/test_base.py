"""General test of wizard.py"""

import os
import sys
import logging
import inspect
from unittest import TestCase
from subprocess import PIPE, Popen as popen

SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
LIB_DIR = SCRIPT_DIR + "/../lib"
sys.path.append(LIB_DIR)
import datamodel
from encrypt import Encryption
from lock import Lock
from openstack_utils import Openstack

class TestWizardBaseLine(TestCase):
    """Wizard baseline tests"""
    def test_entrypoints(self):
        """Test wizard entry points"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        exit_status = os.system('wizard --test')
        assert exit_status == 0
        exit_status = os.system('wizard -t')
        assert exit_status == 0

    #def test_usage_information(self):
    #    """Test wizard --help via direct subprocess call"""
    #    self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
    #    print(self.log)
    #    output = popen(['wizard', '--help'], stdout=PIPE).communicate()[0]
    #    self.assertTrue('usage:' in str(output))
       
    #def test_locking(self):
    #    """Test wizard lock class"""
    #    self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
    #    print(self.log)

    #    # make sure lock does not exist
    #    lock_file = "/tmp/wizard.lck"
    #    if os.path.isdir(lock_file):
    #        try:
    #            os.rmdir(lock_file)
    #        except:
    #            self.assertTrue(False)

    #    lock = Lock(lock_file)
    #    lock.get_lock()
    #    self.assertTrue(os.path.isdir(lock_file))
    #    lock.release_lock()
    #    self.assertFalse(os.path.isdir(lock_file))

    #def test_encryption(self):
    #    """Test wizard encryption class"""
    #    self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
    #    print(self.log)

    #    # make sure keyfile does not exist
    #    tmpfile = "/tmp/keyfile.tmp"
    #    if os.path.isfile(tmpfile):
    #        try:
    #            os.remove(tmpfile)
    #        except:
    #            self.assertTrue(False)

    #    encryption = Encryption(tmpfile)
    #    original_string = "This is a test string"
    #    encrypted_string = encryption.encrypt_password(original_string)
    #    unencrypted_string = encryption.decrypt_password(encrypted_string)
    #    self.assertTrue(unencrypted_string == original_string)
        
    def test_launch_instances(self):
        """Launch OpenStack Instances (On-Boarding Targets)"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

        # get du
        cicd_du = "cs-integration.platform9.horse"
        du = datamodel.get_du_metadata(cicd_du)
        print(du)

        # define spec for isntances being launched
        instance_spec = {
        }
        openstack = Openstack(du)
        openstack.launch_instance(instance_spec)
