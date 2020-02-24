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
        instance_spec = {
            "server" : {
                "name" : instance_name,
                "flavorRef" : "4b76ff99-7f5f-4bcf-ae50-79aa37acc8ce",
                "imageRef" : "9091915e-5272-4b35-a4bb-5dfec4ffc2e8",
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
                instance_msg = "failed to launch instance (HTTP response code: {})".format(pf9_response.status_code)
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

        # check for attached volumes
        api_endpoint = "nova/v2.1/{}/servers/{}/os-volume_attachments".format(self.project_id,target_uuid)
        pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint),verify=False, headers=headers)
        if pf9_response.status_code == 200:
            tmp_server = json.loads(pf9_response.text)
            if len(tmp_server['volumeAttachments']) > 0:
                for vol_metadata in tmp_server['volumeAttachments']:
                  api_endpoint = "{}/nova/v2.1/{}/servers/{}/os-volume_attachments/{}".format(self.du_url,self.project_id,target_uuid,vol_metadata['volumeId'])
                  delete_vol = requests.delete(api_endpoint,headers=headers,verify=False)
                  if delete_vol.status_code != 202:
                      return(False)
        else:
            return(False)

        # delete instance
        delete_response = requests.delete(target_delete_url,headers=headers,verify=False)
        if delete_response.status_code == 204:
            return(False)
        else:
            return(True)


    def wait_for_instance(self, instance_uuid):
        TIMEOUT = 3
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


    def get_floating_ip(self, instance_uuid):
        sys.stdout.write("getting floating ip from pool\n")
        try:
            api_endpoint = "nova/v2.1/os-floating-ips"
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            pf9_response = requests.get("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers)
            if pf9_response.status_code != 200:
                return(None, None)

            # parse api response
            try:
                json_response = json.loads(pf9_response.text)
                for fip in json_response['floating_ips']:
                    if not fip['instance_id']:
                        return(fip['ip'], fip['id'])
                return(None, None)
            except Exception as ex1:
                return(None, None)
        except:
            return(None, None)


    def assign_fip_to_instance(self, instance_uuid, fip_ip):
        sys.stdout.write("assigning floating ip {} to instance {}\n".format(fip_ip, instance_uuid))

        fip_payload = {
            "addFloatingIp" : {
                "address": fip_ip
            }
        }

        try:
            api_endpoint = "nova/v2.1/{}/servers/{}/action".format(self.project_id, instance_uuid)
            headers = { 'content-type': 'application/json', 'X-Auth-Token': self.token }
            pf9_response = requests.post("{}/{}".format(self.du_url,api_endpoint), verify=False, headers=headers, data=json.dumps(fip_payload))
            if pf9_response.status_code == 202:
                return(True)
        except Exception as ex2:
            return(False)

        return(False)


    def launch_in_nstances(self,num_instances,instance_basename):
        SLEEP_BETWEEN_LAUNCH = 2
        instance_num = 1
        instance_uuids = []
        while instance_num <= num_instances:
            instance_name = "{}{}".format(instance_basename,str(instance_num).zfill(2))
            instance_uuid, instance_msg = self.launch_instance(instance_name)
            if instance_uuid:
                instance_uuids.append(instance_uuid)
            instance_num += 1
            time.sleep(SLEEP_BETWEEN_LAUNCH)
        return(instance_uuids)

