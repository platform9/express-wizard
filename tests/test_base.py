"""General test of wizard.py"""

import os
import sys
import time
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

    def get_pmo_importdata_path(self):
        return("{}/../scripts/integration-tests/cs-integration-kvm01.json.tpl".format(os.path.dirname(os.path.realpath(__file__))))

    def get_pmk_importdata_path(self):
        return("{}/../scripts/integration-tests/cs-integration-kvm01.json.tpl".format(os.path.dirname(os.path.realpath(__file__))))

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


    def get_num_instances_pmk(self, config_file):
        if sys.version_info[0] == 2:
            cicd_config = ConfigParser.ConfigParser()
        else:
            cicd_config = configparser.ConfigParser()

        try:
            cicd_config.read(config_file)
            return(cicd_config.get('source_region','num_instances_pmk'))
        except Exception as ex:
            return(False)


    def get_num_instances_pmo(self, config_file):
        if sys.version_info[0] == 2:
            cicd_config = ConfigParser.ConfigParser()
        else:
            cicd_config = configparser.ConfigParser()

        try:
            cicd_config.read(config_file)
            return(cicd_config.get('source_region','num_instances_pmo'))
        except Exception as ex:
            return(False)

    def delete_all_instances(du, instance_uuids):
        from openstack_utils import Openstack
        openstack = Openstack(du)

        for tmp_uuid in instance_uuids:
            self.log.warning("INFO: deleting instance: {}".format(tmp_uuid))
            openstack.delete_instance(tmp_uuid)

    def test_launch_instances(self):
        """Launch OpenStack Instances (On-Boarding Targets)"""
        logging.basicConfig()
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

        # validate config file exists
        config_file = self.get_cicd_config_path()
        self.log.warning("config_file={}\n".format(config_file))
        self.assertTrue(os.path.isfile(config_file))

        STATIC_ENCRYPTION_KEY = "tSlJjykbyXqnDDxj6AIRa6052xvrng6OCBowyRSlITc="
        if STATIC_ENCRYPTION_KEY != "":
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

            # initialize pf9_lockdir
            pf9_lockdir = "{}/lock".format(pf9_home)
            if not os.path.isdir(pf9_lockdir):
                try:
                    os.mkdir(pf9_lockdir)
                except:
                    self.log.warning("ERROR: failed to create directory: {}".format(pf9_lockdir))
                    self.assertTrue(False)

            # call wizard (to import region)
            exit_status = os.system("wizard -i --jsonImport {} -k {}".format(self.get_region_importdata_path(),STATIC_ENCRYPTION_KEY))
            assert exit_status == 0

            # read config file: scripts/integration-tests/integration-tests.conf
            du_url = self.get_du_url(config_file)
            self.log.warning("du_url={}".format(du_url))
            self.assertTrue(du_url)
            num_instances_pmo = int(self.get_num_instances_pmo(config_file))
            self.log.warning("num_instances_pmo={}".format(num_instances_pmo))
            self.assertTrue(num_instances_pmo)
            num_instances_pmk = int(self.get_num_instances_pmk(config_file))
            self.log.warning("num_instances_pmk={}".format(num_instances_pmk))
            self.assertTrue(num_instances_pmk)

            # get du record
            du = datamodel.get_du_metadata(du_url)
            self.assertTrue(du)

            # instantiate openstack library
            from openstack_utils import Openstack
            openstack = Openstack(du)

            # launch PMO instances
            SLEEP_LAUNCH = 2
            instance_num = 1
            instance_uuids = []
            while instance_num <= num_instances_pmo:
                instance_name = "ci-kvm{}".format(str(instance_num).zfill(2))
                instance_uuid, instance_msg = openstack.launch_instance(instance_name)
                self.assertTrue(instance_uuid)
                instance_uuids.append(instance_uuid)
                instance_num += 1
                time.sleep(SLEEP_LAUNCH)

            # timeout loop : wait for instances to boot
            booted_instances = []
            TIMEOUT = 5
            POLL_INTERVAL = 15
            timeout = int(time.time()) + (60 * TIMEOUT)
            flag_all_active = False
            while True:
                # loop over all instances and get status
                for tmp_uuid in instance_uuids:
                    instance_status = openstack.get_instance_status(tmp_uuid)
                    if instance_status == "ACTIVE":
                        if not tmp_uuid in booted_instances:
                            booted_instances.append(tmp_uuid)
                    time.sleep(1)

                # check if all instances have become active
                tmp_flag = True
                for tmp_uuid in instance_uuids:
                    if not tmp_uuid in booted_instances:
                        tmp_flag = False
                        break

                if tmp_flag:
                    flag_all_active = True
                    break
                elif int(time.time()) > timeout:
                    break
                else:
                    time.sleep(POLL_INTERVAL)

            # enforce TIMEOUT
            if not flag_all_active:
                self.log.warning("TIMEOUT: waiting for all instances to become active")
                self.log.warning("instance_uuids = {}".format(instance_uuids))
                self.delete_all_instances(du, instance_uuids)
                self.assertTrue(False)

            # assign floating IP to instance
            uuid_fip_map = {}
            POLL_INTERVAL_FIP = 10
            for tmp_uuid in instance_uuids:
                fip_ip, fip_id = openstack.get_floating_ip(tmp_uuid)
                self.assertTrue(fip_ip)
                fip_status = openstack.assign_fip_to_instance(tmp_uuid, fip_ip)
                self.assertTrue(fip_status)
                uuid_fip_map.update({tmp_uuid:fip_ip})
                time.sleep(POLL_INTERVAL_FIP)

            # parameterize pmo import template
            pmo_import_file = self.get_pmo_importdata_path()
            try:
                file = open(pmo_import_file, 'r')
                template_data = file.read()
                instance_num = 1
                for tmp_uuid in instance_uuids:
                    ip_tag = "<ip-kvm{}>".format(str(instance_num).zfill(2))
                    self.log.warning("Parameterizing {} : {} = {}".format(ip_tag,uuid_fip_map[tmp_uuid],tmp_uuid))
                    template_data.replace(ip_tag,uuid_fip_map[tmp_uuid])
                    instance_num += 1
            except:
                self.log.warning("ERROR: failed to read import file to: {}".format(pmo_import_file))
                self.assertTrue(False)

            # write parameterized template to tmpfile
            try:
                tmpfile = "/tmp/pf9-pmo-import.json"
                tmpfile_fh = open(tmpfile, 'w')
                file.write(template_data)
            except:
                self.log.warning("ERROR: failed to write import file: {}".format(tmpfile))
                self.assertTrue(False)

            # DBG
            exit_status = os.system("echo '------------------' ; cat {} ; echo '----------------------'".format(tmpfile))

            # call wizard (to on-board region)
            #exit_status = os.system("wizard --jsonImport {}".format(tmpfile))
            #assert exit_status == 0

            # cleanup (delete instances)
            self.delete_all_instances(du,instance_uuids)

