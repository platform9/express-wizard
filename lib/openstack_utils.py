"""libs/openstack.py"""
import os
import sys
import time
import datamodel
import du_utils
import requests
import json

class Openstack:
    """Manage Openstack Instances"""
    def __init__(self, du):
        self.project_id, self.token = du_utils.login_du(du['url'], du['username'], du['password'], du['tenant'])
        if self.token == None:
            sys.stdout.write("ERROR: failed to login to region: {}".format(du['url']))
            sys.exit(1)
        self.du_url = du['url']

    def get_instance_status(self, instance_uuid):
        try:
            api_endpoint = "nova/v2.1/{}/servers/{}".format(self.project_id, instance_uuid)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers)
            if pf9_response.status_code != 200:
                return(None)

            # parse api response
            try:
                json_response = json.loads(pf9_response.text)
                return(json_response['server']['status'])
            except Exception as ex1:
                return(None)
        except Exception as ex2:
            return(None)

        return(None)

    def launch_instance(self, instance_name):
        """Launch an Openstack Instance"""

        instance_uuid = None
        instance_msg = "instance launched successfully"

        # note: removed to boot from volume "imageRef" : "9091915e-5272-4b35-a4bb-5dfec4ffc2e8"
        # note: added boot-from-volume code:
        # "block_device_mapping_v2": [{
        #    "boot_index": "0",
        #    "uuid": "a5e7ace4-f685-415a-af0d-075f0c663a01",
        #    "source_type": "image",
        #    "volume_size": "8",
        #    "destination_type": "volume",
        #    "delete_on_termination": True,
        #    "disk_bus": "scsi"}],

        instance_spec = {
            "server" : {
                "name" : instance_name,
                "imageRef" : "a5e7ace4-f685-415a-af0d-075f0c663a01",
                "flavorRef" : "4b76ff99-7f5f-4bcf-ae50-79aa37acc8ce",
                "key_name" : "danwright-mac01",
                "security_groups": [
                    { "name": "cs-integration" }
                ],
                "networks" : [
                    { "uuid" : "b8e1371f-d7bb-4670-a583-682e289a4724" }
                ]
            }
        }

        sys.stdout.write("launching instance: {}\n".format(instance_name))
        try:
            api_endpoint = "nova/v2.1/{}/servers".format(self.project_id)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            pf9_response = requests.post("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers, data=json.dumps(instance_spec))
            if pf9_response.status_code != 202:
                instance_msg = "failed to launch instance (HTTP response code: {}|{})".format(pf9_response.status_code,pf9_response.json())
                return(instance_uuid,instance_msg)

            # parse api response
            try:
                json_response = json.loads(pf9_response.text)
                instance_uuid = json_response['server']['id']
            except Exception as ex1:
                return(instance_uuid,ex1.message)
        except Exception as ex2:
            return(instance_uuid,ex2.message)

        return(instance_uuid,instance_msg)


    def get_instance_metadata(self, target_uuid):
        """Get Matadata for Openstack Instance"""

        # get server record
        api_endpoint = "nova/v2.1/{}/servers/{}".format(self.project_id,target_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
        pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return(False)
        tmp_server = json.loads(pf9_response.text)
        return(tmp_server)


    def get_instance_ip(self, target_uuid):
        """Get IP Address for Openstack Instance"""

        # get server record
        api_endpoint = "nova/v2.1/{}/servers/{}".format(self.project_id,target_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
        pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return(False)
        tmp_server = json.loads(pf9_response.text)
        return(tmp_server['server']['addresses']['auto_allocated_network_cs-dev'][0]['addr'])


    def delete_instance(self, target_uuid):
        """Delete an Openstack Instance"""

        # get server record
        api_endpoint = "nova/v2.1/{}/servers/{}".format(self.project_id,target_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
        pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return(False)
        tmp_server = json.loads(pf9_response.text)
        target_delete_url = tmp_server['server']['links'][0]['href']

        # delete instance
        delete_response = requests.delete(target_delete_url,headers=headers,verify=False)
        if delete_response.status_code == 204:
            return(False)
        else:
            return(True)


    def wait_for_instance(self, instance_uuid):
        TIMEOUT = 10
        POLL_INTERVAL = 10
        timeout = int(time.time()) + (60 * TIMEOUT)
        flag_instance_is_active = False
        sys.stdout.write("waiting for instance {} to become active: ".format(instance_uuid))
        sys.stdout.flush()

        while True:
            n = self.get_instance_status(instance_uuid)
            if n and n == "ACTIVE":
                flag_instance_is_active = True
                break
            elif int(time.time()) > timeout:
                break
            else:
                time.sleep(POLL_INTERVAL)

        # enforce TIMEOUT
        if not flag_instance_is_active:
            sys.stdout.write("TIMEOUT\n")
            sys.stdout.flush()
            return(False)

        sys.stdout.write("OK\n")
        sys.stdout.flush()
        return(True)


    def get_floating_ip(self):
        sys.stdout.write("getting floating ip from pool\n")
        try:
            api_endpoint = "neutron/v2.0/floatingips"
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers)
            if pf9_response.status_code != 200:
                return(False)

            # parse api response
            try:
                json_response = json.loads(pf9_response.text)
                for fip in json_response['floatingips']:
                    if not fip['fixed_ip_address']:
                        return(fip)
                return(False)
            except Exception as ex1:
                return(False)
        except:
            return(False)


    def assign_fip_to_instance(self, fip_metadata, instance_ip):
        neutron_port_id = None
        try:
            api_endpoint = "neutron/v2.0/ports"
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers)
            json_response = json.loads(pf9_response.text)
            for p in json_response['ports']:
                for fixed_ip in p['fixed_ips']:
                    if fixed_ip['ip_address'] == instance_ip:
                        neutron_port_id = p['id']
        except Exception as ex2:
            return(False)

        if not neutron_port_id:
              return(False)

        fip_payload = {
            "floatingip": {
                "port_id": neutron_port_id
            }
        }

        try:
            api_endpoint = "neutron/v2.0/floatingips/{}".format(fip_metadata['id'])
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            pf9_response = requests.put("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers, data=json.dumps(fip_payload))
            if pf9_response.status_code == 200:
                return(True)
        except Exception as ex:
            sys.stdout.write("{}\n".format(ex.message))
            return(False)

        return(False)


    def launch_n_instances(self,num_instances,instance_basename):
        SLEEP_BETWEEN_LAUNCH = 2
        instance_num = 1
        instance_uuids = []
        instance_messages = []
        while instance_num <= num_instances:
            instance_name = "{}{}".format(instance_basename,str(instance_num).zfill(2))
            instance_uuid, instance_msg = self.launch_instance(instance_name)
            if instance_uuid:
                instance_uuids.append(instance_uuid)
            instance_messages.append(instance_msg)
            instance_num += 1
            time.sleep(SLEEP_BETWEEN_LAUNCH)
        return(instance_uuids, instance_messages)


    def wait_for_instances(self,instance_uuids):
        booted_instances = []
        start_time = int(time.time())
        TIMEOUT = 15
        POLL_INTERVAL = 30
        timeout = int(time.time()) + (60 * TIMEOUT)
        flag_all_active = False
        while True:
            # loop over all instances and get status
            for tmp_uuid in instance_uuids:
                instance_status = self.get_instance_status(tmp_uuid)
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
            return(False,0)

        # calculate time to launch all instances
        end_time = int(time.time())
        time_elapsed = end_time - start_time

        return(True,time_elapsed)
