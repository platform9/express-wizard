import requests
import globals
import json
import pmk_utils
import datamodel
import ssh_utils


def discover_du_hosts(du_url, du_type, project_id, token, flag_validate_ssh):
    discovered_hosts = []
    try:
        api_endpoint = "resmgr/v1/hosts"
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers)
        if pf9_response.status_code != 200:
            return(discovered_hosts)
    except:
        return(discovered_hosts)

    # parse resmgr response
    try:
        json_response = json.loads(pf9_response.text)
    except:
        return(discovered_hosts)

    # process/classify discovered hosts
    cnt = 0
    for host in json_response:
        # get IP
        try:
            discover_ips = ",".join(host['extensions']['ip_address']['data'])
        except:
            discover_ips = ""

        # initialize flags
        flag_unassigned = True
        flag_kvm = False
        flag_kubernetes = False

        # get roles
        role_kube = "n"
        role_nova = "n"
        role_glance = "n"
        role_cinder = "n"
        role_designate = "n"
        for role in host['roles']:
            if role == "pf9-kube":
                flag_unassigned = False
                flag_kubernetes = True
                role_kube = "y"
            if role == "pf9-glance-role":
                flag_unassigned = False
                flag_kvm = True
                role_glance = "y"
            if role == "pf9-cindervolume-base":
                flag_unassigned = False
                flag_kvm = True
                role_cinder = "y"
            if role == "pf9-ostackhost-neutron":
                flag_unassigned = False
                flag_kvm = True
                role_nova = "y"
            if role == "pf9-designate":
                flag_unassigned = False
                flag_kvm = True
                role_designate = "y"

        host_primary_ip = ""
        if flag_kubernetes:
            host_type = "kubernetes"
            qbert_nodetype = pmk_utils.qbert_get_nodetype(du_url, project_id, token, host['id'])
            host_primary_ip = pmk_utils.qbert_get_primary_ip(du_url, project_id, token, host['id'])
            qbert_cluster_uuid = pmk_utils.qbert_get_cluster_uuid(du_url, project_id, token, host['id'])
            qbert_cluster_name = pmk_utils.qbert_get_cluster_name(du_url, project_id, token, qbert_cluster_uuid)
            qbert_attach_status = pmk_utils.qbert_get_cluster_attach_status(du_url, project_id, token, host['id'])
        if flag_kvm:
            host_type = "kvm"
        if flag_unassigned:
            host_type = "unassigned"

        if flag_kvm or flag_unassigned:
            if discover_ips != "":
                discovered_ips_list = discover_ips.split(',')
                if len(discovered_ips_list) == 1:
                    host_primary_ip = discovered_ips_list[0]
        
        # validate ssh connectivity
        if host_primary_ip == "":
            ssh_status = "No Primary IP"
        else:
            du_metadata = datamodel.get_du_metadata(du_url)
            if du_metadata:
                if flag_validate_ssh:
                    ssh_status = ssh_utils.ssh_validate_login(du_metadata, host_primary_ip)
                    if ssh_status == True:
                        ssh_status = "OK"
                    else:
                        ssh_status = "Failed"
                else:
                    ssh_status = "Unvalidated"
            else:
                ssh_status = "Unvalidated"

        host_record = datamodel.create_host_entry()
        host_record['du_url'] = du_url
        host_record['du_type'] = du_type
        host_record['ip'] = host_primary_ip
        host_record['uuid'] = host['id']
        host_record['ip_interfaces'] = discover_ips
        host_record['du_host_type'] = host_type
        host_record['hostname'] = host['info']['hostname']
        host_record['record_source'] = "Discovered"
        host_record['ssh_status'] = ssh_status
        host_record['bond_config'] = ""
        host_record['pf9-kube'] = role_kube
        host_record['nova'] = role_nova
        host_record['glance'] = role_glance
        host_record['cinder'] = role_cinder
        host_record['designate'] = role_designate
        if flag_kubernetes:
            host_record['node_type'] = qbert_nodetype
            host_record['cluster_name'] = qbert_cluster_name
            host_record['cluster_uuid'] = qbert_cluster_uuid
            host_record['cluster_attach_status'] = qbert_attach_status
        discovered_hosts.append(host_record)

    return(discovered_hosts)


