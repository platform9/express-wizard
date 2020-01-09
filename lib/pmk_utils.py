import sys
import requests
import json
import datamodel

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


def credsmanager_is_responding(du_url, project_id, token):
    try:
        api_endpoint = "credsmanager"
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers, timeout=5)
        if pf9_response.status_code == 200:
            return True
    except:
        return False

    return False


def discover_du_clusters(du_url, du_type, project_id, token):
    discovered_clusters = []
    try:
        api_endpoint = "qbert/v3/{}/clusters".format(project_id)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return(discovered_clusters)
    except:
        return(discovered_clusters)

    # parse resmgr response
    try:
        json_response = json.loads(pf9_response.text)
    except:
        return(discovered_clusters)

    # process discovered clusters
    for cluster in json_response:
        cluster_record = datamodel.create_cluster_entry()
        cluster_record['du_url'] = du_url
        cluster_record['name'] = cluster['name']
        cluster_record['uuid'] = cluster['uuid']
        cluster_record['record_source'] = "Discovered"
        cluster_record['containers_cidr'] = cluster['containersCidr']
        cluster_record['services_cidr'] = cluster['servicesCidr']
        cluster_record['master_vip_ipv4'] = cluster['masterVipIpv4']
        cluster_record['master_vip_iface'] = cluster['masterVipIface']
        cluster_record['metallb_cidr'] = cluster['metallbCidr']
        cluster_record['privileged'] = cluster['privileged']
        cluster_record['app_catalog_enabled'] = cluster['appCatalogEnabled']
        cluster_record['allow_workloads_on_master'] = cluster['allowWorkloadsOnMaster']
        discovered_clusters.append(cluster_record)

    return(discovered_clusters)


def get_nodepool_id(du_url,project_id,token):
    try:
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        api_endpoint = "qbert/v3/{}/cloudProviders".format(project_id)
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return None

        # parse resmgr response
        try:
            json_response = json.loads(pf9_response.text)
        except:
            return None

        for item in json_response:
            if item['type'] == 'local':
                return(item['nodePoolUuid'])
    except:
        return None


def create_cluster(du_url,project_id,token,cluster):
    sys.stdout.write("--> Creating Cluster: {}\n".format(cluster['name']))
    nodepool_id = get_nodepool_id(du_url,project_id,token)
    if nodepool_id == None:
        sys.stdout.write("ERROR: failed to get nodepool_id for cloud provider\n")
        return(None)

    # configure cluster
    cluster_create_payload = {
        "name": cluster['name'],
        "nodePoolUuid": nodepool_id,
        "containersCidr": cluster['containers_cidr'],
        "servicesCidr": cluster['services_cidr'],
        "masterVipIpv4": cluster['master_vip_ipv4'],
        "masterVipIface": cluster['master_vip_iface'],
        "metallbCidr": cluster['metallb_cidr'],
        "privileged": cluster['privileged'],
        "appCatalogEnabled": cluster['app_catalog_enabled'],
        "allowWorkloadsOnMaster": cluster['allow_workloads_on_master'],
        "enableMetallb": True
    }

    # create cluster
    try:
        api_endpoint = "qbert/v3/{}/clusters".format(project_id)
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.post("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers, data=json.dumps(cluster_create_payload))
    except:
        sys.stdout.write("ERROR: failed to create cluster\n")
        return(None)

    # parse resmgr response
    cluster_uuid = None
    try:
        json_response = json.loads(pf9_response.text)
        cluster_uuid = json_response['uuid']
    except:
        sys.stdout.write("INFO: failed to create cluster (failed to retrieve the uuid)\n")
    return(cluster_uuid)


