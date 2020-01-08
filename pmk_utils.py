import requests
import json

def qbert_is_responding(du_url, project_id, token):
    try:
        api_endpoint = "qbert/v3/{}/nodes".format(project_id)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            return True
    except:
        return False

    return False


def qbert_get_nodetype(du_url, project_id, token, node_uuid):
    node_type = ""
    try:
        api_endpoint = "qbert/v3/{}/nodes/{}".format(project_id, node_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                if json_response['isMaster'] == 1:
                    return("master")
                else:
                    return("worker")

            except:
                return(node_type)
    except:
        return node_type

    return node_type


def qbert_get_primary_ip(du_url, project_id, token, node_uuid):
    primary_ip = ""
    try:
        api_endpoint = "qbert/v3/{}/nodes/{}".format(project_id, node_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                return(json_response['primaryIp'])
            except:
                return(primary_ip)
    except:
        return primary_ip

    return primary_ip


def qbert_get_cluster_uuid(du_url, project_id, token, node_uuid):
    cluster_uuid = ""
    try:
        api_endpoint = "qbert/v3/{}/nodes/{}".format(project_id, node_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                return(json_response['clusterUuid'])
            except:
                return(cluster_uuid)
    except:
        return cluster_uuid

    return cluster_uuid


def qbert_get_cluster_name(du_url, project_id, token, cluster_uuid):
    cluster_name = ""
    try:
        api_endpoint = "qbert/v3/{}/clusters/{}".format(project_id, cluster_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                return(json_response['name'])
            except:
                return(cluster_name)
    except:
        return cluster_name

    return cluster_name


def qbert_get_cluster_attach_status(du_url, project_id, token, node_uuid):
    attach_status = "Unattached"
    try:
        api_endpoint = "qbert/v3/{}/nodes/{}".format(project_id, node_uuid)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code == 200:
            try:
                json_response = json.loads(pf9_response.text)
                if json_response['clusterName']:
                    if json_response['status'] == "OK":
                        attach_status = "Attached"
                    else:
                        attach_status = json_response['status']
                return(attach_status)
            except:
                return(attach_status)
    except:
        return(attach_status)

    return(attach_status)


