"""lib/du_utils.py"""
import requests
import json
import globals
import pmk_utils
from encrypt import Encryption


def login(du_host, username, password, project_name):
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)
    password = encryption.decrypt_password(password)
    url = "{}/keystone/v3/auth/tokens?nocatalog".format(du_host)
    body = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"id": "default"},
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "name": project_name,
                    "domain": {"id": "default"}
                }
            }
        }
    }
    try:
        resp = requests.post(url,
                             data=json.dumps(body),
                             headers={'content-type': 'application/json'},
                             verify=False)
        json_response = json.loads(resp.text)
    except:
        fail_bootstrap("failed to parse json result")
    return json_response['token']['project']['id'], resp.headers['X-Subject-Token']


def login_du(du_url, du_user, du_password, du_tenant):
    try:
        project_id, token = login(du_url,
                                  du_user,
                                  du_password,
                                  du_tenant)
    except:
        return(None, None)

    return(project_id, token)


def get_sub_dus(du):
    project_id, token = login(du['url'],
                              du['username'],
                              du['password'],
                              du['tenant'])

    if token is None:
        return(None, None)

    try:
        api_endpoint = "keystone/v3/services?type=regionInfo"
        headers = {'content-type': 'application/json', 'X-Auth-Token': token}
        pf9_response = requests.get("{}/{}".format(du['url'], api_endpoint),
                                    verify=False,
                                    headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                services_id = json_response['services'][0]['id']
                if services_id:
                    api_endpoint = "keystone/v3/endpoints?service_id={}".format(services_id)
                    try:
                        pf9_subresponse = requests.get("{}/{}".format(du['url'], api_endpoint),
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


def get_du_type(du_url, du_user, du_password, du_tenant):
    project_id, token = login(du_url,
                              du_user,
                              du_password,
                              du_tenant)
    region_type = "-"
    qbert_status = pmk_utils.qbert_is_responding(du_url, project_id, token)
    if qbert_status:
        region_type = "Kubernetes"
        credsmanager_status = pmk_utils.credsmanager_is_responding(du_url, project_id, token)
        if credsmanager_status:
            region_type = "KVM/Kubernetes"
        else:
            region_type = "VMware"
    else:
        credsmanager_status = pmk_utils.credsmanager_is_responding(du_url, project_id, token)
        if credsmanager_status:
            region_type = "KVM"
        else:
            region_type = "VMware"
    return region_type
