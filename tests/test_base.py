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
import resmgr_utils
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

    def xtest_encryption(self):
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
        
    def get_region_sshkey_path(self):
        return("{}/../id_rsa".format(os.path.dirname(os.path.realpath(__file__))))

    def get_keyfile_path(self):
        from os.path import expanduser
        return("{}/.pf9/db/.keyfile".format(expanduser("~")))

    def get_pf9home_path(self):
        from os.path import expanduser
        return("{}/.pf9".format(expanduser("~")))

    def get_clihome_path(self):
        from os.path import expanduser
        return("{}/pf9".format(expanduser("~")))

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


    def init_express_basedir(self):
        base_dirs = [
            self.get_pf9home_path(),
            self.get_clihome_path(),
            "{}/log".format(self.get_clihome_path()),
            "{}/db".format(self.get_pf9home_path()),
            "{}/lock".format(self.get_pf9home_path())
        ]

        # initialize basedirs
        for base_dir in base_dirs:
            if not os.path.isdir(base_dir):
                try:
                    os.mkdir(base_dir)
                except:
                    return(False)

        return(True)


    def pmk_integration_test(self, ci_config, os_version):
        self.log.info("****************************************")
        self.log.info("**** STARTING PMK INTEGRATION TESTS")
        self.log.info("**** OS for K8s Nodes: {}".format(os_version))
        self.log.info("****************************************")

        # instantiate openstack library (for source region)
        self.log.info(">>> Initialize Openstack Integration (includes logging in to DU)")
        du = datamodel.get_du_metadata(ci_config.get('source_region','du_url'))
        self.assertTrue(du)
        from openstack_utils import Openstack
        openstack = Openstack(du)

        # get number of instances to launch (must correlate with host stanza in import json)
        num_instances = int(ci_config.get('source_region','num_instances_pmk'))

        # DBG:
        flag_skip_launch = False
        if flag_skip_launch:
            instance_uuids = [
                "dae6e968-6f8e-4789-82e3-8f9391db1db1"
            ]
            uuid_fip_map = {
                "dae6e968-6f8e-4789-82e3-8f9391db1db1": "104.143.12.173"
            }
        else:
           instance_uuids = []
        
        # launch instances
        ci_hostname = "ci-k8s"
        if instance_uuids:
            self.log.info(">>> Skipping Launching Openstack Instances")
        else:
            self.log.info(">>> Launching {} Openstack Instances for PMK Integration Test (OS={}):".format(num_instances,os_version))
            self.log.info("du_url = {}".format(du['url']))
            instance_uuids, instance_messages = openstack.launch_n_instances(num_instances,ci_hostname,os_version,self.log.info)
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
                
            # wait for instances to boot
            boot_status, launch_elapsed_time = openstack.wait_for_instances(instance_uuids)
            if not boot_status:
                self.log.info("TIMEOUT: waiting for all instances to become active")
                self.delete_all_instances(du, instance_uuids)
                self.assertTrue(False)
            self.log.info("all instances booted successfully (time to launch all instances: {} seconds)".format(launch_elapsed_time))

            # assign floating IP to instance
            control_plane_pause = 30
            self.log.info(">>> Control Plane Pause (API/backend propogation): {} seconds".format(control_plane_pause))
            time.sleep(control_plane_pause)
            self.log.info(">>> Adding Floating IP Interfaces (Public) to Instances")
            uuid_fip_map = {}
            POLL_INTERVAL_FIP = 10
            for tmp_uuid in instance_uuids:
                fip_metadata = openstack.get_floating_ip()
                if not fip_metadata:
                    self.delete_all_instances(du,instance_uuids)
                    self.assertTrue(fip_metadata)
                fip_status = openstack.assign_fip_to_instance(fip_metadata, openstack.get_instance_ip(tmp_uuid), self.log.info)
                if not fip_status:
                    self.delete_all_instances(du,instance_uuids)
                    self.assertTrue(fip_status)
                uuid_fip_map.update({tmp_uuid:fip_metadata['floating_ip_address']})
                self.log.info("Added {} to {}".format(fip_metadata['floating_ip_address'],tmp_uuid))
                time.sleep(POLL_INTERVAL_FIP)

            # get target du
            target_du_url = ci_config.get('pmk_region','du_url')

            # read PMK import template
            self.log.info(">>> Parameterizing Import Template for Target Region: {}".format(target_du_url))
            target_import_file = "{}/../scripts/integration-tests/cs-integration-k8s01.json.tpl".format(os.path.dirname(os.path.realpath(__file__)))
            if os.path.isfile(target_import_file):
                try:
                    with open(target_import_file) as json_file:
                        import_json = json.load(json_file)
                except Exception as ex:
                    self.log.info("JSON IMPORT EXCEPTION: {}".format(ex))

            # parameterize PMK import template
            self.log.info("parameterizing IP addresses")
            instance_num = 1
            for tmp_uuid in instance_uuids:
                # parameterize IP address
                target_hostname = "{}{}".format(ci_hostname,str(instance_num).zfill(2))
                for tmp_host in import_json['hosts']:
                    if tmp_host['hostname'] == target_hostname:
                        tmp_host['ip'] = uuid_fip_map[tmp_uuid]
                        tmp_host['public_ip'] = uuid_fip_map[tmp_uuid]

                instance_num += 1

            # parameterize ssh-keypath in region
            self.log.info("parameterizing region ssh key")
            import_json['region']['auth_ssh_key'] = self.get_region_sshkey_path()

            # parameterize interfae name for VIP
            if os_version in ["centos74"]:
                master_vip_iface = "eth0"
            elif os_version in ["ubuntu16","ubuntu18"]:
                master_vip_iface = "ens3"
            else:
                self.log.info("Failed to map interface name for master VIP")
                self.assertTrue(False)

            self.log.info("parameterizing interface name for master VIP: {}".format(master_vip_iface))
            import_json['clusters'][0]['master_vip_iface'] = master_vip_iface

            # parameterize username for remote access
            if os_version in ["centos74"]:
                self.log.info("parameterizing region auth username: centos")
                import_json['region']['auth_username'] = "centos"
            elif os_version in ["ubuntu16","ubuntu18"]:
                self.log.info("parameterizing region auth username: ubuntu")
                import_json['region']['auth_username'] = "ubuntu"
            else:
                self.log.info("failed to parameterize region auth username")
                self.assertTrue(False)

            # write parameterized template to tmpfile
            tmpfile = "/tmp/pf9-pmk-import.json"
            with open(tmpfile, 'w') as outfile:
                json.dump(import_json, outfile)

            # Import Region
            cmd = "wizard --jsonImport {} --skipActions".format(tmpfile)
            self.log.info(">>> Importing Target Region: {}".format(target_du_url))
            self.log.info("running: {}".format(cmd))
            exit_status, stdout = self.run_cmd(cmd)
            if exit_status != 0:
                self.log.info("ERROR: failed to import region")
                self.assertTrue(False)

            # get target_du
            self.log.info(">>> Getting Configuration for Target DU: {}".format(target_du_url))
            target_du = datamodel.get_du_metadata(target_du_url)
            self.assertTrue(target_du)
            self.log.info("target DU: {}".format(target_du['url']))

            # wait for floating IPs to respond on all instances (if any timeout, assert)
            self.log.info(">>> Waiting for Floating IP Addresses to Become Reachable")
            for tmp_uuid in instance_uuids:
                try:
                    ip_is_responding = ssh_utils.wait_for_ip(target_du,uuid_fip_map[tmp_uuid],self.log.info)
                except Exception as ex:
                    self.log.info("EXCEPTION: {}".format(ex))

                if not ip_is_responding:
                    self.assertTrue(False)
            self.log.info("INFO: all floating IPs are responding")

        # Run Integration Test
        cmd = "wizard --jsonImport {}".format(tmpfile)
        self.log.info(">>> Starting PMK Integration Test (Importing Region)")
        self.log.info("running: {}".format(cmd))
        ci_exit_status, stdout = self.run_cmd(cmd)
        if ci_exit_status == 0:
            self.log.info("INTEGRAION TEST STATUS : PASSED")
        else:
            self.log.info("INTEGRAION TEST STATUS : FAILED")

        # display import log
        self.log.info("================ START: Integration Test Log ================")
        for line in stdout:
            self.log.info(line.strip())
        self.log.info("================ END: Integration Test Log ================")

        # deauthorize hosts
        if ci_exit_status == 0:
            #self.log.info(">>> Deauthorizing Hosts")
            #du_hosts = datamodel.get_hosts(target_du_url)
            #if du_hosts:
            #    for h in du_hosts:
            #        if h['uuid'] != "":
            #            self.log.info("{}... ".format(h['hostname']))
            #            if (resmgr_utils.deauth_host(du,h['uuid'])):
            #                self.log.info("OK\n")
            #            else:
            #                self.log.info("FAILED\n")
            # cleanup (delete instances)
            #self.log.info("CLEANUP: deleting all instances")
            #self.delete_all_instances(du,instance_uuids)
            return(True)
        else:
            return(False)


    def test_ci(self):
        """Run Continuous Integration Tests"""
        logging.basicConfig()
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)

        self.log.info("*********************************************")
        self.log.info("**** INITIALIZING CONTINUOUS INTEGRATION ****")
        self.log.info("*********************************************")

        # validate/read config file
        config_file = "{}/../scripts/integration-tests/integration-tests.conf".format(os.path.dirname(os.path.realpath(__file__)))
        self.log.info(">>> Reading Configuration file: {}".format(config_file))
        self.assertTrue(os.path.isfile(config_file))
        if sys.version_info[0] == 2:
            ci_config = ConfigParser.ConfigParser()
        else:
            ci_config = configparser.ConfigParser()

        try:
            ci_config.read(config_file)
        except Exception as ex:
            self.log.info("ERROR: {}".format(ex))
            self.assertTrue(False)

        self.log.info(">>> Initializing Encryption")
        EMS_VAULT_KEY = os.environ.get('EMS_KEY')
        if not EMS_VAULT_KEY:
            self.log.info("Failed to get encryption key from environment")
            self.assertTrue(False)

        # inititialize base directories
        self.log.info(">>> Initializing Installation Directories")
        if not (self.init_express_basedir()):
            self.log.info("failed to initialize base directories")

        # read import template for source region
        self.log.info(">>> Parameterizing Import Template for Source Region")
        source_import_file = "{}/../scripts/integration-tests/cloud.platform9.net.json.tpl".format(os.path.dirname(os.path.realpath(__file__)))
        if os.path.isfile(source_import_file):
            try:
                with open(source_import_file) as json_file:
                    import_json = json.load(json_file)
            except Exception as ex:
                self.log.info("JSON IMPORT EXCEPTION: {}".format(ex))

        # parameterize import template
        self.log.info("parameterizing region ssh key")
        import_json['region']['auth_ssh_key'] = self.get_region_sshkey_path()

        # write template to tmpfile
        tmpfile = "/tmp/pf9-cloud-import.json"
        with open(tmpfile, 'w') as outfile:
            json.dump(import_json, outfile)

        # import source region
        self.log.info(">>> Importing Source Region: cloud.platform9.net")
        cmd = "wizard -i --jsonImport {} -k {}".format(tmpfile,EMS_VAULT_KEY)
        self.log.info("    Running: '{}'".format(cmd))
        exit_status, stdout = self.run_cmd(cmd)
        if exit_status != 0:
            for l in stdout:
                self.log.info(l.strip())
            self.assertTrue(False)

        # set permissions on sskkey
        try:
            os.chmod(self.get_region_sshkey_path(), 0o400)
        except:
            self.log.info("ERROR: failed to set permissions on sshkey: {}".format(self.get_region_sshkey_path()))
            self.assertTrue(False)

        # run integration tests: PMK
        os_versions = [
            "centos74",
            "ubuntu16",
            "ubuntu18"
        ]
        os_versions = ["ubuntu16"]
        for os_version in os_versions:
            if not (self.pmk_integration_test(ci_config,os_version)):
                self.log.info("CI-CD : FAILED")
                self.assertTrue(False)

        # end of integration test
        self.log.info("CI-CD : COMPLETE (reached the end of the script without asserting)")
