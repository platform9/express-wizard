"""libs/pf9_region.py"""
import os
import sys
import datamodel
import requests
import du_utils
import json
import globals

class PF9_Region:
    """Interact with a Platform9 Region"""
    def __init__(self, region_url):
        self.region_url = region_url
        self.project_id = None
        self.token = None
        self.login_region()

    def login_region(self):
        du = datamodel.get_du_metadata(self.region_url)
        if du:
            project_id, token = du_utils.login_du(du['url'], du['username'], du['password'], du['tenant'])
            if token:
                self.token = token
            if project_id:
                self.project_id = project_id

    def get_config(self):
        return(datamodel.get_du_metadata(self.region_url))

    def get_sub_dus(self):
        try:
            api_endpoint = "keystone/v3/services?type=regionInfo"
            headers = {'content-type': 'application/json', 'X-Auth-Token': self.token}
            pf9_response = requests.get("{}/{}".format(self.region_url, api_endpoint),
                                        verify=False,
                                        headers=headers)
            if pf9_response.status_code == 200:
                try:
                    json_response = json.loads(pf9_response.text)
                    services_id = json_response['services'][0]['id']
                    if services_id:
                        api_endpoint = "keystone/v3/endpoints?service_id={}".format(services_id)
                        try:
                            pf9_subresponse = requests.get("{}/{}".format(self.region_url, api_endpoint),
                                                           verify=False,
                                                           headers=headers)
                            if pf9_subresponse.status_code == 200:
                                try:
                                    json_subresponse = json.loads(pf9_subresponse.text)
                                    url_list = []
                                    du_name_list = []
                                    for ep in json_subresponse['endpoints']:
                                        baseurl = ep['url'].replace('https://', '').split('/')[0]
                                        if not baseurl in url_list:
                                            url_list.append(baseurl)
                                            du_name_list.append(ep['region'])
                                    return(url_list, du_name_list)
                                except:
                                    return(None, None)
                        except:
                            return(None, None)
                    return(None, None)
                except:
                    return(None, None)
        except:
            return(None, None)

        return(None, None)

