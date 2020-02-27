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
import json
import ssh_utils
from encrypt import Encryption
from lock import Lock
from openstack_utils import Openstack
try:
    import ConfigParser
except ImportError:
    import configparser


class TestWizardBaseLine(TestCase):
    """Wizard baseline tests"""
    def xtest_entrypoints(self):
        """Test wizard entry points"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        exit_status = os.system('wizard --test')
        assert exit_status == 0
        exit_status = os.system('wizard -t')
        assert exit_status == 0

    def xtest_usage_information(self):
        """Test wizard --help via direct subprocess call"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)
        output = popen(['wizard', '--help'], stdout=PIPE).communicate()[0]
        self.assertTrue('usage:' in str(output))
       
    def xtest_locking(self):
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

    def get_region_sshkey_path(self):
        return("{}/../id_rsa".format(os.path.dirname(os.path.realpath(__file__))))

    def get_pmo_importdata_path(self):
        return("{}/../scripts/integration-tests/cs-integration-kvm01.json.tpl".format(os.path.dirname(os.path.realpath(__file__))))

    def get_pmk_importdata_path(self):
        return("{}/../scripts/integration-tests/cs-integration-k8s01.json.tpl".format(os.path.dirname(os.path.realpath(__file__))))

    def get_pf9cloud_importdata_path(self):
        return("{}/../scripts/integration-tests/cloud.platform9.net.json.tpl".format(os.path.dirname(os.path.realpath(__file__))))

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

    def delete_all_instances(self, du, instance_uuids):
        SLEEP_BETWEEN_DELETE = 5
        from openstack_utils import Openstack
        openstack = Openstack(du)

        for tmp_uuid in instance_uuids:
            self.log.info("INFO: deleting instance: {}".format(tmp_uuid))
            openstack.delete_instance(tmp_uuid)
            time.sleep(SLEEP_BETWEEN_DELETE)

    def run_cmd(self,cmd):
        cmd_stdout = ""
        tmpfile = "/tmp/pf9.{}.tmp".format(os.getppid())
        cmd_exitcode = os.system("{} > {} 2>&1".format(cmd, tmpfile))

        # read output of command
        if os.path.isfile(tmpfile):
            try:
                fh_tmpfile = open(tmpfile, 'r')
                cmd_stdout = fh_tmpfile.readlines()
            except:
                None

        os.remove(tmpfile)
        return cmd_exitcode, cmd_stdout

    def launch_instances(self, num_instances):
        """Launch OpenStack Instances (On-Boarding Targets)"""
        None

    def init_express_basedir(self):
        # initialize pf9_home
        pf9_home = self.get_pf9home_path()
        if not os.path.isdir(pf9_home):
            try:
                os.mkdir(pf9_home)
            except:
                return(False)

        # initialize pf9_home_db
        pf9_home_db = "{}/db".format(pf9_home)
        if not os.path.isdir(pf9_home_db):
            try:
                os.mkdir(pf9_home_db)
            except:
                return(False)

        # initialize pf9_lockdir
        pf9_lockdir = "{}/lock".format(pf9_home)
        if not os.path.isdir(pf9_lockdir):
            try:
                os.mkdir(pf9_lockdir)
            except:
                return(False)

        return(True)


    def pmo_integration_test(self, config_file, du, openstack):
        self.log.info("\n****************************************")
        self.log.info("**** STARTING PMO INTEGRATION TESTS ****")
        self.log.info("****************************************")

        num_instances = int(self.get_num_instances_pmo(config_file))

        # launch instances
        ci_hostname = "ci-kvm"
        self.log.info(">>> Launching {} Openstack Instances for PMO Integration Test:".format(num_instances))
        self.log.info("du_url = {}".format(du['url']))
        instance_uuids = openstack.launch_n_instances(num_instances,ci_hostname)
        if not instance_uuids:
            self.log.info("ERROR: failed to launch Openstack {} instances".format(num_instances))
            self.assertTrue(False)
        if len(instance_uuids) < num_instances:
            self.log.info("ERROR: failed to launch Openstack {} instances".format(num_instances))
            self.assertTrue(False)
        self.log.info("all instances launched successfully - waiting for them to boot...".format(num_instances))
            

        # wait for instances to boot
        boot_status, launch_elapsed_time = openstack.wait_for_instances(instance_uuids)
        if not boot_status:
            self.log.info("TIMEOUT: waiting for all instances to become active")
            self.delete_all_instances(du, instance_uuids)
            self.assertTrue(False)
        self.log.info("all instances booted successfully (time to launch all instances: {} seconds)".format(launch_elapsed_time))

        # assign floating IP to instance
        self.log.info(">>> Adding Floating IP Interfaces (Public) to Instances")
        uuid_fip_map = {}
        POLL_INTERVAL_FIP = 10
        for tmp_uuid in instance_uuids:
            fip_metadata = openstack.get_floating_ip()
            if not fip_metadata:
                self.delete_all_instances(du,instance_uuids)
                self.assertTrue(fip_metadata)
            fip_status = openstack.assign_fip_to_instance(fip_metadata, openstack.get_instance_ip(tmp_uuid))
            if not fip_status:
                self.delete_all_instances(du,instance_uuids)
                self.assertTrue(fip_status)
            uuid_fip_map.update({tmp_uuid:fip_metadata['floating_ip_address']})
            self.log.info("Added {} to {}".format(fip_metadata['floating_ip_address'],tmp_uuid))
            time.sleep(POLL_INTERVAL_FIP)

        # read PMO import template
        self.log.info(">>> Parameterizing Import Template for PMO Integration Test")
        target_import_file = self.get_pmo_importdata_path()
        if os.path.isfile(target_import_file):
            try:
                with open(target_import_file) as json_file:
                    import_json = json.load(json_file)
            except Exception as ex:
                self.log.info("JSON IMPORT EXCEPTION: {}".format(ex.message))

        # parameterize PMO import template
        instance_num = 1
        for tmp_uuid in instance_uuids:
            # parameterize IP address
            target_hostname = "{}{}".format(ci_hostname,str(instance_num).zfill(2))
            for tmp_host in import_json['hosts']:
                if tmp_host['hostname'] == target_hostname:
                    tmp_host['ip'] = uuid_fip_map[tmp_uuid]

            instance_num += 1

        # parameterize ssh-keypath in region
        import_json['region']['auth_ssh_key'] = self.get_region_sshkey_path()

        # parameterize ssh-keypath in auth-profiles (they all use the same key as the region)
        for tmp_auth in import_json['auth-profiles']:
            tmp_auth['auth_ssh_key'] = self.get_region_sshkey_path()

        # write parameterized template to tmpfile
        tmpfile = "/tmp/pf9-pmo-import.json"
        with open(tmpfile, 'w') as outfile:
            json.dump(import_json, outfile)

        # call wizard (to on-board region)
        self.log.info(">>> Starting PMO Integration Test (Importing Region)")
        exit_status, stdout = self.run_cmd("wizard --jsonImport {}".format(tmpfile))
        if exit_status == 0:
            self.log.info("INTEGRAION TEST STATUS : PASSED")
        else:
            self.log.info("INTEGRAION TEST STATUS : FAILED")

        # display import log
        self.log.info("================ START: Region Import Log ================")
        for line in stdout:
            self.log.info(line.strip())
        self.log.info("================ END: Region Import Log ================")

        # cleanup (delete instances)
        self.log.info("CLEANUP: deleting all instances")
        self.delete_all_instances(du,instance_uuids)


    def pmk_integration_test(self, config_file, du, openstack):
        self.log.info("\n****************************************")
        self.log.info("**** STARTING PMK INTEGRATION TESTS ****")
        self.log.info("****************************************")

        num_instances = int(self.get_num_instances_pmk(config_file))

        # launch instances
        ci_hostname = "ci-k8s"
        self.log.info(">>> Launching {} Openstack Instances for PMK Integration Test:".format(num_instances))
        self.log.info("du_url = {}".format(du['url']))
        instance_uuids, instance_messages = openstack.launch_n_instances(num_instances,ci_hostname)
        if instance_messages:
            self.log.info("Launch Status:")
            for m in instance_messages:
                self.log.info("--> {}".format(m))
        if not instance_uuids:
            self.log.info("ERROR: failed to launch Openstack {} instances".format(num_instances))
            self.assertTrue(False)
        if len(instance_uuids) < num_instances:
            self.log.info("ERROR: failed to launch Openstack {} instances".format(num_instances))
            self.assertTrue(False)
        self.log.info("all instances launched successfully - waiting for them to boot...".format(num_instances))
            
        # wait for instances to boot
        boot_status, launch_elapsed_time = openstack.wait_for_instances(instance_uuids)
        if not boot_status:
            self.log.info("TIMEOUT: waiting for all instances to become active")
            self.delete_all_instances(du, instance_uuids)
            self.assertTrue(False)
        self.log.info("all instances booted successfully (time to launch all instances: {} seconds)".format(launch_elapsed_time))

        # assign floating IP to instance
        self.log.info(">>> Adding Floating IP Interfaces (Public) to Instances")
        uuid_fip_map = {}
        POLL_INTERVAL_FIP = 10
        for tmp_uuid in instance_uuids:
            fip_metadata = openstack.get_floating_ip()
            if not fip_metadata:
                self.delete_all_instances(du,instance_uuids)
                self.assertTrue(fip_metadata)
            fip_status = openstack.assign_fip_to_instance(fip_metadata, openstack.get_instance_ip(tmp_uuid))
            if not fip_status:
                self.delete_all_instances(du,instance_uuids)
                self.assertTrue(fip_status)
            uuid_fip_map.update({tmp_uuid:fip_metadata['floating_ip_address']})
            self.log.info("Added {} to {}".format(fip_metadata['floating_ip_address'],tmp_uuid))
            time.sleep(POLL_INTERVAL_FIP)

        # wait for floating IPs to respond on all instances (if any timeout, assert)
        self.log.info(">>> Waiting for Floating IP Addresses to Become Reachable")
        for tmp_uuid in instance_uuids:
            try:
                ip_is_responding = ssh_utils.wait_for_ip(du,uuid_fip_map[tmp_uuid])
                self.log.info("DBG: ip_is_responding = {}".format(ip_is_responding))
            except Exception as ex:
                self.log.info("EXCEPTION: {}".format(ex.message))

            if not ip_is_responding:
                self.assertTrue(False)

        # read PMK import template
        self.log.info(">>> Parameterizing Import Template for PMK Integration Test")
        target_import_file = self.get_pmk_importdata_path()
        if os.path.isfile(target_import_file):
            try:
                with open(target_import_file) as json_file:
                    import_json = json.load(json_file)
            except Exception as ex:
                self.log.info("JSON IMPORT EXCEPTION: {}".format(ex.message))

        # parameterize PMK import template
        instance_num = 1
        for tmp_uuid in instance_uuids:
            # parameterize IP address
            target_hostname = "{}{}".format(ci_hostname,str(instance_num).zfill(2))
            for tmp_host in import_json['hosts']:
                if tmp_host['hostname'] == target_hostname:
                    tmp_host['ip'] = uuid_fip_map[tmp_uuid]

            instance_num += 1

        # parameterize ssh-keypath in region
        import_json['region']['auth_ssh_key'] = self.get_region_sshkey_path()

        # write parameterized template to tmpfile
        tmpfile = "/tmp/pf9-pmk-import.json"
        with open(tmpfile, 'w') as outfile:
            json.dump(import_json, outfile)

        self.log.info("================ START: Region Import File ================")
        cmd = "cat {} | python -m json.tool".format(tmpfile)
        exit_status, stdout = self.run_cmd(cmd)
        for l in stdout:
            self.log.info(l.strip())
        self.log.info("================ END: Region Import File ================")

        # call wizard (to on-board region)
        cmd = "wizard --jsonImport {}".format(tmpfile)
        self.log.info(">>> Starting PMK Integration Test (Importing Region)")
        self.log.info("running: {}".format(cmd))
        exit_status, stdout = self.run_cmd(cmd)
        if exit_status == 0:
            self.log.info("INTEGRAION TEST STATUS : PASSED")
        else:
            self.log.info("INTEGRAION TEST STATUS : FAILED")

        # display import log
        self.log.info("================ START: Region Import Log ================")
        for line in stdout:
            self.log.info(line.strip())
        self.log.info("================ END: Region Import Log ================")

        # cleanup (delete instances)
        #self.log.info("CLEANUP: deleting all instances")
        #self.delete_all_instances(du,instance_uuids)


    def test_integration(self):
        """Run Integration Tests"""
        logging.basicConfig()
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

        self.log.info("\n************************************")
        self.log.info("**** STARTING INTEGRATION TESTS ****")
        self.log.info("************************************")

        # validate config file exists
        config_file = self.get_cicd_config_path()
        self.log.info(">>> Validate Configuration File: {}".format(config_file))
        self.assertTrue(os.path.isfile(config_file))

        self.log.info(">>> Getting Encryption Key")
        EMS_VAULT_KEY = os.environ.get('EMS_KEY')
        #EMS_VAULT_KEY = "tSlJjykbyXqnDDxj6AIRa6052xvrng6OCBowyRSlITc="
        if not EMS_VAULT_KEY:
            self.log.info("Failed to get key for encryption from environment")
            self.assertTrue(False)

        # inititialize ~/.pf9
        self.log.info(">>> Initializing Installation Directory")
        init_status = self.init_express_basedir()
        if not init_status:
            self.log.info("failed to initialize EMS basedir")

        ################################################################################################
        # read cloud.platform9.net import template
        self.log.info(">>> Parameterizing Import Template for Platform9 Cloud Region")
        target_import_file = self.get_pf9cloud_importdata_path()
        if os.path.isfile(target_import_file):
            try:
                with open(target_import_file) as json_file:
                    import_json = json.load(json_file)
            except Exception as ex:
                self.log.info("JSON IMPORT EXCEPTION: {}".format(ex.message))

        # parameterize ssh-keypath in region
        import_json['region']['auth_ssh_key'] = self.get_region_sshkey_path()

        # write parameterized template to tmpfile
        tmpfile = "/tmp/pf9-cloud-import.json"
        with open(tmpfile, 'w') as outfile:
            json.dump(import_json, outfile)

        self.log.info("================ START: Platform9 Cloud Region Import File ================")
        cmd = "cat {} | python -m json.tool".format(tmpfile)
        exit_status, stdout = self.run_cmd(cmd)
        for l in stdout:
            self.log.info(l.strip())
        self.log.info("================ END: Platform9 Cloud Region Import File ================")

        ################################################################################################

        # import region: cloud.platform9.net
        self.log.info(">>> Importing Region: cloud.platform9.net")
        cmd = "wizard -i --jsonImport {} -k {}".format(tmpfile,EMS_VAULT_KEY)
        self.log.info("INFO running: {}".format(cmd))
        exit_status, stdout = self.run_cmd(cmd)
        for l in stdout:
            self.log.info(l.strip())
        if exit_status != 0:
            self.assertTrue(False)

        # read du_url (from config file)
        du_url = self.get_du_url(config_file)

        # get du record
        du = datamodel.get_du_metadata(du_url)
        self.assertTrue(du)

        # instantiate openstack library
        from openstack_utils import Openstack
        openstack = Openstack(du)

        # DBG
        ########################################################################################################
        # ip_addr = "131.153.255.204"
        # self.log.info("waiting for IP: {}".format(ip_addr))
        # ip_is_responding = ssh_utils.wait_for_ip(du,ip_addr)
        # print("ip_is_responding={}".format(ip_is_responding))
        # self.assertTrue(False)
        ########################################################################################################

        # DBG
        ########################################################################################################
        # tmp_uuid = "aa9286fe-568e-4e92-b5cf-9abe1228fe5b"
        # tmp_uuid = "937d349c-1f6d-4002-8ec1-1e3097de709a"
        # fip_metadata = openstack.get_floating_ip()
        # sys.stdout.write("RETURNED FIP METADATA = {}\n---------------------\n".format(fip_metadata))
        # fip_status = openstack.assign_fip_to_instance(fip_metadata, openstack.get_instance_ip(tmp_uuid))
        # print("fip_status = {}".format(fip_status))
        # self.assertTrue(False)
        ########################################################################################################

        # set permissions on sskkey
        try:
            os.chmod(self.get_region_sshkey_path(), 0o400)
        except:
            self.log.info("ERROR: failed to set permissions on sshkey: {}".format(self.get_region_sshkey_path()))
            self.assertTrue(False)

        # run integration test: PMO
        #self.pmo_integration_test(config_file, du, openstack)

        # run integration test: PMK
        self.pmk_integration_test(config_file, du, openstack)

        # end of integration test
        self.log.info("CI-CD : COMPLETE (reached the end of the script within asserting)")
