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
try:
    import ConfigParser
except ImportError:
    import configparser


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
       
    def test_locking(self):
        """Test wizard lock class"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

        # make sure lock does not exist
        lock_file = "/tmp/wizard.lck"
        if os.path.isdir(lock_file):
            try:
                os.rmdir(lock_file)
            except:
                self.assertTrue(False)

        lock = Lock(lock_file)
        lock.get_lock()
        self.assertTrue(os.path.isdir(lock_file))
        lock.release_lock()
        self.assertFalse(os.path.isdir(lock_file))

    def test_encryption(self):
        """Test wizard encryption class"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

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
        
    def get_cicd_config_path(self):
        return("{}/../scripts/integration-tests/integration-tests.conf".format(os.path.dirname(os.path.realpath(__file__))))

    def get_region_importdata_path(self):
        return("{}/../scripts/integration-tests/cloud.platform9.net".format(os.path.dirname(os.path.realpath(__file__))))

    def get_keyfile_path(self):
        from os.path import expanduser
        return("{}/.pf9/db/.keyfile".format(expanduser("~")))

    def get_pf9home_path(self):
        from os.path import expanduser
        return("{}/.pf9".format(expanduser("~")))

    def get_du_url(self, config_file):
        if sys.version_info[0] == 2:
            cicd_config = ConfigParser.ConfigParser()
        else:
            cicd_config = configparser.ConfigParser()

        try:
            cicd_config.read(config_file)
            return(cicd_config.get('source_region','du_url'))
        except Exception as ex:
            return(False)


    def test_launch_instances(self):
        """Launch OpenStack Instances (On-Boarding Targets)"""
        logging.basicConfig()
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

        # validate config file exists
        config_file = self.get_cicd_config_path()
        self.log.warning("config_file={}\n".format(config_file))
        self.assertTrue(os.path.isfile(config_file))

        # validate ENCRYPTION_KEY (a secret managed by Travis-CI)
        ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
        if not ENCRYPTION_KEY:
            self.log.warning("ENCRYPTION_KEY: environment variable not defined - skipping Integration Tests")
        else:
            # initialize pf9_home
            pf9_home = self.get_pf9home_path()
            if not os.path.isdir(pf9_home):
                try:
                    os.mkdir(pf9_home)
                except:
                    self.log.warning("ERROR: failed to create directory: {}".format(pf9_home))
                    self.assertTrue(False)

            # initialize pf9_home_db
            pf9_home_db = "{}/db".format(pf9_home)
            if not os.path.isdir(pf9_home_db):
                try:
                    os.mkdir(pf9_home_db)
                except:
                    self.log.warning("ERROR: failed to create directory: {}".format(pf9_home_db))
                    self.assertTrue(False)

            # initialize ENCRYPTION_KEY_FILE
            try:
                data_file_fh = open(self.get_keyfile_path(), "w")
                data_file_fh.write("{}".format(ENCRYPTION_KEY))
                data_file_fh.close()
            except:
                self.log.warning("ERROR: failed to write file: {}".format(self.get_keyfile_path()))
                self.assertTrue(False)
            self.assertTrue(os.path.isfile(data_file))

            # call wizard (to import region)
            exit_status = os.system("wizard -i --jsonImport {}".format(self.get_region_importdata_path()))
            assert exit_status == 0

            # read config file: scripts/integration-tests/integration-tests.conf
            du_url = self.get_du_url(config_file)
            self.log.warning("du_url={}".format(du_url))
            self.assertTrue(du_url)
            du = datamodel.get_du_metadata(du_url)
            self.assertTrue(du)

            # launch instance and wait for it to become active
            from openstack_utils import Openstack
            openstack = Openstack(du)
            instance_uuid, instance_msg = openstack.launch_instance()
            self.assertTrue(instance_uuid)
            instance_is_active = openstack.wait_for_instance(instance_uuid)
            self.assertTrue(instance_is_active)

            # assign floating IP to instance
            fip_ip, fip_id = openstack.get_floating_ip(instance_uuid)
            self.assertTrue(fip_ip)
            fip_status = openstack.assign_fip_to_instance(instance_uuid, fip_ip)
            self.assertTrue(fip_status)



