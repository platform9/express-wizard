####################################################################################################
## PF9-Wizard | Onboarding Tool for Platform9 
## Copyright(c) 2019 Platform9 Systems, Inc.
####################################################################################################
# To-Do:
# 1. Call Express CLI for PMK
# 2. Hierarchical/Scalable Data Model
# 3. Add Region : Improve error recovery when DU auth fails
####################################################################################################
import os
import sys
from os.path import expanduser
import du_utils
import pmk_utils
import reports
import datamodel
import user_io
import interview

################################################################################
# early functions
def fail(m=None):
    sys.stdout.write("ASSERT: {}\n".format(m))
    sys.exit(1)

if not sys.version_info[0] in (2,3):
    fail("Unsupported Python Version: {}\n".format(sys.version_info[0]))

################################################################################
# module imports
try:
    import requests,urllib3,json,argparse,prettytable,signal,getpass,argparse,subprocess,time,pprint
except:
    except_str = str(sys.exc_info()[1])
    module_name = except_str.split(' ')[-1]
    fail("Failed to import module: {} (try running 'pip install {}')".format(sys.exc_info()[1],module_name))

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# input functions
def _parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--init", "-i", help="Initialize Configuration (delete all regions/hosts)", action="store_true")
    return ap.parse_args()


def get_du_type(du_url, project_id, token):
    region_type = "-"
    qbert_status = pmk_utils.qbert_is_responding(du_url, project_id, token)
    if qbert_status == True:
        region_type = "Kubernetes"
        credsmanager_status = pmk_utils.credsmanager_is_responding(du_url, project_id, token)
        if credsmanager_status == True:
            region_type = "KVM/Kubernetes"
        else:
            region_type = "VMware"
    else:
        credsmanager_status = pmk_utils.credsmanager_is_responding(du_url, project_id, token)
        if credsmanager_status == True:
            region_type = "KVM"
        else:
            region_type = "VMware"
    return(region_type)


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


def discover_du_hosts(du_url, du_type, project_id, token):
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
            du_metadata = datamodel.get_du_metadata(du_url,CONFIG_FILE)
            if du_metadata:
                ssh_status = ssh_validate_login(du_metadata, host_primary_ip)
                if ssh_status == True:
                    ssh_status = "OK"
                else:
                    ssh_status = "Failed"
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


def get_du_hosts(du_url, project_id, token):
    num_hosts = 0
    try:
        api_endpoint = "resmgr/v1/hosts"
        headers = { 'content-type': 'application/json', 'X-Auth-Token': token }
        pf9_response = requests.get("{}/{}".format(du_url,api_endpoint), verify=False, headers=headers, timeout=5)
        if pf9_response.status_code != 200:
            return(num_hosts)

        try:
            json_response = json.loads(pf9_response.text)
        except:
            return(num_hosts)

        for item in json_response:
            num_hosts += 1
    except:
        return(num_hosts)

    return(num_hosts)


def dump_var(target_var):
    from inspect import getmembers
    from pprint import pprint
    pprint(getmembers(target_var))


def map_yn(map_key):
    if map_key == "y":
        return("Enabled")
    elif map_key == "n":
        return("Disabled")
    else:
        return("failed-to-map")


def ssh_validate_login(du_metadata, host_ip):
    if du_metadata['auth_type'] == "simple":
        return(False)
    elif du_metadata['auth_type'] == "sshkey":
        cmd = "ssh -o StrictHostKeyChecking=no -i {} {}@{} 'echo 201'".format(du_metadata['auth_ssh_key'], du_metadata['auth_username'], host_ip)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            return(True)
        else:
            return(False)

    return(False)


def add_edit_du():
    if not os.path.isdir(CONFIG_DIR):
        return(None)
    elif not os.path.isfile(CONFIG_FILE):
        return("define-new-du")
    else:
        current_config = get_configs()
        if len(current_config) == 0:
            return(None)
        else:
            cnt = 1
            allowed_values = ['q','n']
            sys.stdout.write("\n")
            for du in current_config:
                sys.stdout.write("{}. {}\n".format(cnt,du['url']))
                allowed_values.append(str(cnt))
                cnt += 1
            sys.stdout.write("\n")
            user_input = user_io.read_kbd("Select Region to Update/Rediscover (enter 'n' to create a New Region)", allowed_values, '', True, True)
            if user_input == "q":
                return(None)
            elif user_input == "n":
                return("define-new-du")
            else:
                idx = int(user_input) - 1
                return(current_config[idx]['url'])
        return(None)


def select_du():
    if not os.path.isdir(CONFIG_DIR):
        sys.stdout.write("\nNo regions have been defined yet (run 'Add/Update Region')\n")
    elif not os.path.isfile(CONFIG_FILE):
        sys.stdout.write("\nNo regions have been defined yet (run 'Add/Update Region')\n")
    else:
        current_config = get_configs()
        if len(current_config) == 0:
            sys.stdout.write("\nNo regions have been defined yet (run 'Add/Update Region')\n")
        else:
            cnt = 1
            allowed_values = ['q']
            sys.stdout.write("\n")
            for du in current_config:
                sys.stdout.write("{}. {}\n".format(cnt,du['url']))
                allowed_values.append(str(cnt))
                cnt += 1
            user_input = user_io.read_kbd("Select Region", allowed_values, '', True, True)
            if user_input == "q":
                return({})
            else:
                idx = int(user_input) - 1
                return(current_config[idx])
        return({})


def get_configs(du_url=None):
    du_configs = []
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)

    if not du_url:
        return(du_configs)
    else:
        filtered_du_configs = []
        for du in du_configs:
            if du['url'] == du_url:
                filtered_du_configs.append(du)
        return(filtered_du_configs)


def delete_du(target_du):
    new_du_list = []
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)
        for du in du_configs:
            if du['url'] == target_du['url']:
                sys.stdout.write("--> found target Region\n")
            else:
                new_du_list.append(du)
    else:
        sys.stdout.write("\nERROR: failed to open Region database: {}".format(CONFIG_FILE))

    # update DU database
    try:
        with open(CONFIG_FILE, 'w') as outfile:
            json.dump(new_du_list, outfile)
    except:
        sys.stdout.write("\nERROR: failed to update Region database: {}".format(CONFIG_FILE))


def get_hosts(du_url):
    du_hosts = []
    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            du_hosts = json.load(json_file)

    if du_url == None:
        filtered_hosts = list(du_hosts)
    else:
        filtered_hosts = []
        for du in du_hosts:
            if du['du_url'] == du_url:
                filtered_hosts.append(du)

    return(filtered_hosts)


def write_cluster(cluster):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_clusters = datamodel.get_clusters(None,CLUSTER_FILE)
    if len(current_clusters) == 0:
        current_clusters.append(cluster)
        with open(CLUSTER_FILE, 'w') as outfile:
            json.dump(current_clusters, outfile)
    else:
        update_clusters = []
        flag_found = False
        for c in current_clusters:
            if c['name'] == cluster['name']:
                update_clusters.append(cluster)
                flag_found = True
            else:
                update_clusters.append(c)
        if not flag_found:
            update_clusters.append(cluster)
        with open(CLUSTER_FILE, 'w') as outfile:
            json.dump(update_clusters, outfile)


def write_host(host):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    # get all hosts
    current_hosts = get_hosts(None)
    if len(current_hosts) == 0:
        current_hosts.append(host)
        with open(HOST_FILE, 'w') as outfile:
            json.dump(current_hosts, outfile)
    else:
        update_hosts = []
        flag_found = False
        for h in current_hosts:
            if h['hostname'] == host['hostname'] and h['uuid'] == host['uuid']:
                update_hosts.append(host)
                flag_found = True
            else:
                update_hosts.append(h)
        if not flag_found:
            update_hosts.append(host)
        with open(HOST_FILE, 'w') as outfile:
            json.dump(update_hosts, outfile)


def write_config(du):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_config = get_configs()
    if len(current_config) == 0:
        current_config.append(du)
        with open(CONFIG_FILE, 'w') as outfile:
            json.dump(current_config, outfile)
    else:
        update_config = []
        flag_found = False
        for config in current_config:
            if config['url'] == du['url']:
                update_config.append(du)
                flag_found = True
            else:
                update_config.append(config)
        if not flag_found:
            update_config.append(du)
        with open(CONFIG_FILE, 'w') as outfile:
            json.dump(update_config, outfile)


def add_cluster(du):
    sys.stdout.write("\nAdding Cluster to Region: {}\n".format(du['url']))
    project_id, token = du_utils.login_du(du['url'],du['username'],du['password'],du['tenant'])
    if token == None:
        sys.stdout.write("--> failed to login to region")
    else:
        cluster_metadata = interview.get_cluster_metadata(du, project_id, token, CLUSTER_FILE)
        if cluster_metadata:
            cluster = datamodel.create_cluster_entry()
            cluster['du_url'] = cluster_metadata['du_url']
            cluster['name'] = cluster_metadata['name']
            cluster['record_source'] = "User-Defined"
            cluster['containers_cidr'] = cluster_metadata['containers_cidr']
            cluster['services_cidr'] = cluster_metadata['services_cidr']
            cluster['master_vip_ipv4'] = cluster_metadata['master_vip_ipv4']
            cluster['master_vip_iface'] = cluster_metadata['master_vip_iface']
            cluster['metallb_cidr'] = cluster_metadata['metallb_cidr']
            cluster['privileged'] = cluster_metadata['privileged']
            cluster['app_catalog_enabled'] = cluster_metadata['app_catalog_enabled']
            cluster['allow_workloads_on_master'] = cluster_metadata['allow_workloads_on_master']

            # persist configurtion
            write_cluster(cluster)


def add_host(du):
    sys.stdout.write("\nAdding Host to Region: {}\n".format(du['url']))
    project_id, token = du_utils.login_du(du['url'],du['username'],du['password'],du['tenant'])
    if token == None:
        sys.stdout.write("--> failed to login to region")
    else:
        host_metadata = interview.get_host_metadata(du, project_id, token, HOST_FILE, CONFIG_DIR, CLUSTER_FILE)
        if host_metadata:
            host = datamodel.create_host_entry()
            host['du_url'] = du['url']
            host['du_host_type'] = host_metadata['du_host_type']
            host['ip'] = host_metadata['ip']
            host['uuid'] = host_metadata['uuid']
            host['ip_interfaces'] = host_metadata['ip_interfaces']
            host['hostname'] = host_metadata['hostname']
            host['record_source'] = host_metadata['record_source']
            host['bond_config'] = host_metadata['bond_config']
            host['pf9-kube'] = host_metadata['pf9-kube']
            host['nova'] = host_metadata['nova']
            host['glance'] = host_metadata['glance']
            host['cinder'] = host_metadata['cinder']
            host['designate'] = host_metadata['designate']
            host['node_type'] = host_metadata['node_type']
            host['cluster_name'] = host_metadata['cluster_name']

            # validate ssh connectivity
            if host['ip'] == "":
                ssh_status = "No Primary IP"
            else:
                du_metadata = datamodel.get_du_metadata(du['url'],CONFIG_FILE)
                if du_metadata:
                    ssh_status = ssh_validate_login(du_metadata, host['ip'])
                    if ssh_status == True:
                        ssh_status = "OK"
                    else:
                        ssh_status = "Failed"
                else:
                    ssh_status = "Unvalidated"
            host['ssh_status'] = ssh_status

            # persist configurtion
            write_host(host)


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


def cluster_in_array(target_url,target_name,target_clusters):
    for cluster in target_clusters:
        if cluster['du_url'] == target_url and cluster['name'] == target_name:
            return(True)
    return(False)


def add_region(existing_du_url):
    if existing_du_url == None:
        sys.stdout.write("\nAdding a Region:\n")
    else:
        sys.stdout.write("\nUpdate Region:\n")

    # du_metadata is created by create_du_entry() - and initialized or populated from existing du record
    du_metadata = interview.get_du_creds(existing_du_url,CONFIG_FILE)
    if not du_metadata:
        return(du_metadata)
    else:
        # initialize du data structure
        du = datamodel.create_du_entry()
        du['url'] = du_metadata['du_url']
        du['du_type'] = du_metadata['du_type']
        du['username'] = du_metadata['du_user']
        du['password'] = du_metadata['du_password']
        du['tenant'] = du_metadata['du_tenant']
        du['git_branch'] = du_metadata['git_branch']
        du['region'] = du_metadata['region_name']
        du['region_proxy'] = du_metadata['region_proxy']
        du['dns_list'] = du_metadata['region_dns']
        du['auth_type'] = du_metadata['region_auth_type']
        du['auth_ssh_key'] = du_metadata['auth_ssh_key']
        du['auth_password'] = du_metadata['auth_password']
        du['auth_username'] = du_metadata['auth_username']
        du['bond_ifname'] = du_metadata['region_bond_if_name']
        du['bond_mode'] = du_metadata['region_bond_mode']
        du['bond_mtu'] = du_metadata['region_bond_mtu']

    # initialize list of regions to be discovered
    discover_targets = []

    # define valid region types
    region_types = [
        "q",
        "KVM",
        "Kubernetes",
        "KVM/Kubernetes",
        "VMware"
    ]

    # check for sub-regions
    sub_regions, du_name_list = du_utils.get_sub_dus(du)
    if not sub_regions:
        sys.stdout.write("\nINFO: No Sub-Regions Have Been Detected\n\n")
        discover_targets.append(du)
    else:
        sys.stdout.write("\nThe Following Sub-Regions Have Been Detected:\n\n")
        cnt = 1
        for sub_region in sub_regions:
            if sub_region != du['url'].replace('https://',''):
                sys.stdout.write("{}. {}\n".format(cnt, sub_region))
                cnt += 1
        user_input = user_io.read_kbd("\nDo you want to discover these regions as well", ['q','y','n'], 'n', True, True)
        if user_input == "q":
            return(None)
        elif user_input == "y":
            for sub_region in sub_regions:
                sub_du = datamodel.create_du_entry()
                sub_du['url'] = "https://{}".format(sub_region)
                sub_du['du_type'] = "KVM/Kubernetes"
                sub_du['region'] = du_name_list[sub_regions.index(sub_region)]
                sub_du['username'] = du_metadata['du_user']
                sub_du['password'] = du_metadata['du_password']
                sub_du['tenant'] = du_metadata['du_tenant']
                sub_du['git_branch'] = "master"
                sub_du['region_proxy'] = "-"
                sub_du['dns_list'] = "8.8.8.8,8.8.4.4"
                sub_du['auth_type'] = "sshkey"
                sub_du['auth_ssh_key'] = "~/.ssh/id_rsa"
                sub_du['auth_username'] = "centos"
                sub_du['bond_ifname'] = "bond0"
                sub_du['bond_mode'] = "1"
                sub_du['bond_mtu'] = "9000"
                discover_targets.append(sub_du)
        else:
            du['region'] = du_name_list[sub_regions.index(du_metadata['du_url'].replace('https://',''))]
            discover_targets.append(du)

    # create region (and sub-regions)
    sys.stdout.write("\nCreating Regions:\n")
    for discover_target in discover_targets:
        project_id, token = du_utils.login_du(discover_target['url'],discover_target['username'],discover_target['password'],discover_target['tenant'])
        if project_id:
            sys.stdout.write("--> Adding region: {}\n".format(discover_target['url']))
            region_type = get_du_type(discover_target['url'], project_id, token)
            if discover_target['url'] == du_metadata['du_url']:
                confirmed_region_type = user_io.read_kbd("    Confirm region type ['KVM','Kubernetes','KVM/Kubernetes','VMware']", region_types, du_metadata['du_type'], True, True)
            else:
                confirmed_region_type = user_io.read_kbd("    Confirm region type ['KVM','Kubernetes','KVM/Kubernetes','VMware']", region_types, region_type, True, True)
            discover_target['du_type'] = confirmed_region_type
        write_config(discover_target)

    # perform host discovery
    sys.stdout.write("\nPerforming Host Discovery (this can take a while...)\n")
    for discover_target in discover_targets:
        num_hosts = 0
        sys.stdout.write("--> Discovering hosts for {} region: {}\n".format(discover_target['du_type'],discover_target['url']))
        project_id, token = du_utils.login_du(discover_target['url'],discover_target['username'],discover_target['password'],discover_target['tenant'])
        if project_id:
            discovered_hosts = discover_du_hosts(discover_target['url'], discover_target['du_type'], project_id, token)
            for host in discovered_hosts:
                write_host(host)
                num_hosts += 1
        sys.stdout.write("    # of hosts discovered: {}\n".format(num_hosts))

    # perform cluster discovery
    sys.stdout.write("\nPerforming Cluster Discovery (and provisioning for user-defined clusters)\n")
    for discover_target in discover_targets:
        num_clusters = 0
        if discover_target['du_type'] in ['Kubernetes','KVM/Kubernetes']:
            sys.stdout.write("--> Discovering clusters for {} region: {}\n".format(discover_target['du_type'],discover_target['url']))
            project_id, token = du_utils.login_du(discover_target['url'],discover_target['username'],discover_target['password'],discover_target['tenant'])
            if project_id:
                # discover existing clusters
                discovered_clusters = discover_du_clusters(discover_target['url'], discover_target['du_type'], project_id, token)

                # get existing/user-defined clusters for region
                defined_clusters = datamodel.get_clusters(discover_target['url'],CLUSTER_FILE)

                # create any missing clusters
                for cluster in defined_clusters:
                    cluster_flag = cluster_in_array(cluster['du_url'],cluster['name'],discovered_clusters)
                    if not cluster_in_array(cluster['du_url'],cluster['name'],discovered_clusters):
                        create_cluster(discover_target['url'],project_id,token,cluster)
                    num_clusters += 1

                for cluster in discovered_clusters:
                    write_cluster(cluster)
            sys.stdout.write("    # of clusters discovered: {}\n".format(num_clusters))

    # return
    return(discover_targets)


def get_cluster_uuid(du_url, cluster_name):
    cluster_settings = datamodel.get_cluster_record(du_url, cluster_name, CLUSTER_FILE)
    if cluster_settings:
        return(cluster_settings['uuid'])

    return(None)


def build_express_config(du):
    express_config = "{}/{}.conf".format(CONFIG_DIR, "{}".format(du['url'].replace('https://','')))
    sys.stdout.write("--> Building configuration file: {}\n".format(express_config))

    # write config file
    try:
        express_config_fh = open(express_config, "w")
        express_config_fh.write("manage_hostname|false\n")
        express_config_fh.write("manage_resolver|false\n")
        express_config_fh.write("dns_resolver1|8.8.8.8\n")
        express_config_fh.write("dns_resolver2|8.8.4.4\n")
        express_config_fh.write("os_tenant|{}\n".format(du['tenant']))
        express_config_fh.write("du_url|{}\n".format(du['url']))
        express_config_fh.write("os_username|{}\n".format(du['username']))
        express_config_fh.write("os_password|{}\n".format(du['password']))
        express_config_fh.write("os_region|{}\n".format(du['region']))
        express_config_fh.write("proxy_url|-\n".format(du['region_proxy']))
        express_config_fh.close()
    except:
        sys.stdout.write("ERROR: failed to build configuration file: {}\n{}\n".format(express_config,sys.exc_info()))
        return(None)

    # validate config was written
    if not os.path.isfile(express_config):
        return(None)

    return(express_config)


def build_express_inventory(du, host_entries):
    express_inventory = "{}/{}.inv".format(CONFIG_DIR, "{}".format(du['url'].replace('https://','')))
    sys.stdout.write("--> Building inventory file: {}\n".format(express_inventory))

    # write inventory file
    try:
        express_inventory_fh = open(express_inventory, "w")
        express_inventory_fh.write("# Built by pf9-wizard\n")
        express_inventory_fh.write("[all]\n")
        express_inventory_fh.write("[all:vars]\n")
        express_inventory_fh.write("ansible_user={}\n".format(du['auth_username']))
        if du['auth_type'] == "simple":
            express_inventory_fh.write("ansible_sudo_pass={}\n".format(du['auth_password']))
            express_inventory_fh.write("ansible_ssh_pass={}\n".format(du['auth_password']))
        if du['auth_type'] == "sshkey":
            express_inventory_fh.write("ansible_ssh_private_key_file={}\n".format(du['auth_ssh_key']))
        express_inventory_fh.write("manage_network=True\n")
        express_inventory_fh.write("bond_ifname={}\n".format(du['bond_ifname']))
        express_inventory_fh.write("bond_mode={}\n".format(du['bond_mode']))
        express_inventory_fh.write("bond_mtu={}\n".format(du['bond_mtu']))

        # manage bond stanza
        express_inventory_fh.write("[bond_config]\n")
        for host in host_entries:
            if host['bond_config'] != "":
                express_inventory_fh.write("{} {}\n".format(host['hostname'], host['bond_config']))

        # manage openstack groups
        express_inventory_fh.write("[pmo:children]\n")
        express_inventory_fh.write("hypervisors\n")
        express_inventory_fh.write("glance\n")
        express_inventory_fh.write("cinder\n")

        # manage hypervisors group
        express_inventory_fh.write("[hypervisors]\n")
        cnt = 0
        for host in host_entries:
            if cnt < 2:
                express_inventory_fh.write("{} ansible_host={} vm_console_ip={} ha_cluster_ip={} tunnel_ip={} dhcp=on snat=on\n".format(host['hostname'],host['ip'],host['ip'],host['ip'],host['ip']))
            else:
                express_inventory_fh.write("{} ansible_host={} vm_console_ip={} ha_cluster_ip={} tunnel_ip={}\n".format(host['hostname'],host['ip'],host['ip'],host['ip'],host['ip']))
            cnt += 1

        # manage glance group
        express_inventory_fh.write("[glance]\n")
        cnt = 0
        for host in host_entries:
            if host['glance'] == "y":
                if cnt == 0:
                    express_inventory_fh.write("{} glance_ip={} glance_public_endpoint=True\n".format(host['hostname'],host['ip']))
                else:
                    express_inventory_fh.write("{} glance_ip={}\n".format(host['hostname'],host['ip']))
            cnt += 1

        # manage cinder group
        express_inventory_fh.write("[cinder]\n")
        for host in host_entries:
            if host['cinder'] == "y":
                express_inventory_fh.write("{} cinder_ip={} pvs=['/dev/sdb','/dev/sdc','/dev/sdd','/dev/sde']\n".format(host['hostname'],host['ip']))

        # manage designate group
        express_inventory_fh.write("[designate]\n")
        for host in host_entries:
            if host['designate'] == "y":
                express_inventory_fh.write("{}\n".format(host['hostname']))

        # manage K8s stanza
        express_inventory_fh.write("[pmk:children]\n")
        express_inventory_fh.write("k8s_master\n")
        express_inventory_fh.write("k8s_worker\n")

        # manage K8s_master stanza
        express_inventory_fh.write("[k8s_master]\n")
        for host in host_entries:
            if host['pf9-kube'] == "y" and host['node_type'] == "master":
                if host['cluster_name'] == "Unassigned":
                    express_inventory_fh.write("{} ansible_host={}\n".format(host['hostname'],host['ip']))
                else:
                    cluster_uuid = get_cluster_uuid(du['url'], host['cluster_name'])
                    if cluster_uuid == None:
                        sys.stdout.write("ERROR: failed to lookup cluster UUID for {}\n".format(host['cluster_name']))
                        return(None)
                    express_inventory_fh.write("{} ansible_host={} cluster_uuid={}\n".format(host['hostname'],host['ip'],cluster_uuid))

        # manage K8s_worker stanza
        express_inventory_fh.write("[k8s_worker]\n")
        for host in host_entries:
            if host['pf9-kube'] == "y" and host['node_type'] == "worker":
                if host['cluster_name'] == "Unassigned":
                    express_inventory_fh.write("{} ansible_host={}\n".format(host['hostname'],host['ip']))
                else:
                    cluster_uuid = get_cluster_uuid(du['url'], host['cluster_name'])
                    if cluster_uuid == None:
                        sys.stdout.write("ERROR: failed to lookup cluster UUID for {}\n".format(host['cluster_name']))
                        return(None)
                    express_inventory_fh.write("{} ansible_host={} cluster_uuid={}\n".format(host['hostname'],host['ip'],cluster_uuid))
  
        # close inventory file
        express_inventory_fh.close()
    except Exception as ex:
        sys.stdout.write("ERROR: faild to write inventory file: {}\n".format(ex.message))
        return(None)

    # validate inventory was written
    if not os.path.isfile(express_inventory):
        return(None)

    return(express_inventory)


def checkout_branch(git_branch):
    cmd = "cd {} && git checkout {}".format(EXPRESS_INSTALL_DIR, git_branch)
    exit_status, stdout = run_cmd(cmd)

    current_branch = get_express_branch(git_branch)
    if current_branch != git_branch:
        return(False)

    return(True)


def get_express_branch(git_branch):
    if not os.path.isdir(EXPRESS_INSTALL_DIR):
        return(None)

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(EXPRESS_INSTALL_DIR)
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        return(None)

    return(stdout[0].strip())
    

def install_express(du):
    sys.stdout.write("\nInstalling PF9-Express (branch = {})\n".format(du['git_branch']))
    if not os.path.isdir(EXPRESS_INSTALL_DIR):
        cmd = "git clone {} {}".format(EXPRESS_REPO, EXPRESS_INSTALL_DIR)
        sys.stdout.write("--> cloning repository ({})\n".format(cmd))
        exit_status, stdout = run_cmd(cmd)
        if not os.path.isdir(EXPRESS_INSTALL_DIR):
            sys.stdout.write("ERROR: failed to clone PF9-Express Repository\n")
            return(False)

    sys.stdout.write("--> refreshing repository (git fetch -a)\n")
    cmd = "cd {}; git fetch -a".format(EXPRESS_INSTALL_DIR)
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        sys.stdout.write("ERROR: failed to fetch branches (git fetch -)\n")
        return(False)

    current_branch = get_express_branch(du['git_branch'])
    sys.stdout.write("--> current branch: {}\n".format(current_branch))
    if current_branch != du['git_branch']:
        sys.stdout.write("--> switching branches: {}\n".format(du['git_branch']))
        if (checkout_branch(du['git_branch'])) == False:
            sys.stdout.write("ERROR: failed to checkout git branch: {}\n".format(du['git_branch']))
            return(False)

    cmd = "cd {}; git pull origin {}".format(EXPRESS_INSTALL_DIR,du['git_branch'])
    sys.stdout.write("--> pulling latest code (git pull origin {})\n".format(du['git_branch']))
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        sys.stdout.write("ERROR: failed to pull latest code (git pull origin {})\n".format(du['git_branch']))
        return(False)
 
    return(True)


def wait_for_job(p):
    cnt = 0
    minute = 1
    while True:
        if cnt == 0:
            sys.stdout.write(".")
        elif (cnt % 9) == 0:
            sys.stdout.write("|")
            if (minute % 6) == 0:
                sys.stdout.write("\n")
            cnt = -1
            minute += 1
        else:
            sys.stdout.write(".")
        sys.stdout.flush()
        if p.poll() != None:
            break
        time.sleep(1)
        cnt += 1
    sys.stdout.write("\n")


def tail_log(p):
    last_line = None
    while True:
        current_line = p.stdout.readline()
        if sys.version_info[0] == 2:
            sys.stdout.write(current_line)
        else:
            sys.stdout.write(str(current_line))
        if p.poll() != None:
            if current_line == last_line:
                sys.stdout.write("-------------------- PROCESS COMPETE --------------------\n")
                break
        last_line = current_line


def invoke_express(express_config, express_inventory, target_inventory, role_flag):
    sys.stdout.write("\nRunning PF9-Express\n")
    user_input = user_io.read_kbd("--> Installing PF9-Express Prerequisites, do you want to tail the log (enter 's' to skip)", ['q','y','n','s'], 'n', True, True)
    if user_input == 'q':
        return()
    if user_input in ['y','n']:
        p = subprocess.Popen([PF9_EXPRESS,'-i','-c',express_config],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if user_input == 'y':
            sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
            tail_log(p)
        else:
            wait_for_job(p)

    user_input = user_io.read_kbd("--> Running PF9-Express, do you want to tail the log", ['q','y','n'], 'n', True, True)
    if user_input == 'q':
        return()
    if role_flag == 1:
        if target_inventory in ['k8s_master','ks8_worker']:
            sys.stdout.write("Running: {} -a -b --pmk -c {} -v {} {}\n".format(PF9_EXPRESS,express_config,express_inventory,target_inventory))
            p = subprocess.Popen([PF9_EXPRESS,'-a','-b','--pmk','-c',express_config,'-v',express_inventory,target_inventory],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        else:
            sys.stdout.write("Running: {} -a -b -c {} -v {} {}\n".format(PF9_EXPRESS,express_config,express_inventory,target_inventory))
            p = subprocess.Popen([PF9_EXPRESS,'-a','-b','-c',express_config,'-v',express_inventory,target_inventory],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    else:
        # install pf9-hostagent (skip role assignment)
        if target_inventory in ['k8s_master','ks8_worker']:
            sys.stdout.write("Running: {} -b --pmk -c {} -v {} {}\n".format(PF9_EXPRESS,express_config,express_inventory,target_inventory))
            p = subprocess.Popen([PF9_EXPRESS,'-b','--pmk','-c',express_config,'-v',express_inventory,target_inventory],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        else:
            sys.stdout.write("Running: {} -b -c {} -v {} {}\n".format(PF9_EXPRESS,express_config,express_inventory,target_inventory))
            p = subprocess.Popen([PF9_EXPRESS,'-b','-c',express_config,'-v',express_inventory,target_inventory],stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    if user_input == 'y':
        sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
        tail_log(p)
    else:
        wait_for_job(p)


def run_express(du, host_entries):
    sys.stdout.write("\nPF9-Express Inventory (region type = {})\n".format(du['du_type']))
    if du['du_type'] == "Kubernetes":
        express_inventories = [
            'k8s_master',
            'k8s_worker'
        ]
    elif du['du_type'] == "KVM":
        express_inventories = [
            'all',
            'hypervisors',
            'glance',
            'cinder',
            'designate'
        ]
    else:
        express_inventories = [
            'all',
            'hypervisors',
            'glance',
            'cinder',
            'designate',
            'k8s_master',
            'k8s_worker'
        ]

    cnt = 1
    allowed_values = ['q']
    for inventory in express_inventories:
        sys.stdout.write("    {}. {}\n".format(cnt,inventory))
        allowed_values.append(str(cnt))
        cnt += 1
    custom_idx = cnt
    sys.stdout.write("    {}. custom inventory\n".format(cnt))
    allowed_values.append(str(cnt))
    user_input = user_io.read_kbd("\nSelect Inventory (to run PF9-Express against)", allowed_values, '', True, True)
    if user_input == "q":
        return()
    if int(user_input) != custom_idx:
        idx = int(user_input) - 1
        target_inventory = express_inventories[idx]
    else:
        user_input = user_io.read_kbd("\nInventory Targets (comma/space-delimitted list of hostnames)", [], '', True, True)
        target_inventory = user_input

    sys.stdout.write("\nPF9-Express Role Assignment\n")
    sys.stdout.write("    1. Install Hostagent\n")
    sys.stdout.write("    2. Install Hostagent and Assign Roles\n")
    assign_roles = user_io.read_kbd("\nRole Assignment", ['q','1','2'], '1', True, True)
    if assign_roles == "q":
        return()
    else:
        if int(assign_roles) == 2:
            role_flag = 1
        else:
            role_flag = 0

    flag_installed = install_express(du)
    if flag_installed == True:
        express_config = build_express_config(du)
        if express_config:
            express_inventory = build_express_inventory(du, host_entries)
            if express_inventory:
                invoke_express(express_config, express_inventory, target_inventory, role_flag)
    

def dump_text_file(target_file):
    BAR = "======================================================================================================"
    try:
        target_fh = open(target_file,mode='r')
        sys.stdout.write('\n========== {0:^80} ==========\n'.format(target_file))
        sys.stdout.write(target_fh.read())
        sys.stdout.write('{}\n'.format(BAR))
        target_fh.close()
    except:
        sys.stdout.write("ERROR: failed to open file: {}".format(target_file))


def view_log(log_files):
    cnt = 1
    allowed_values = ['q']
    for log_file in log_files:
        sys.stdout.write("{}. {}\n".format(cnt,log_file))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("Select Log", allowed_values, '', True, True)
    if user_input != "q":
        idx = int(user_input) - 1
        target_log = log_files[idx]
        target_log_path = "{}/{}".format(EXPRESS_LOG_DIR,target_log)
        dump_text_file(target_log_path)


def get_logs():
    log_files = []
    if not os.path.isdir(EXPRESS_LOG_DIR):
        return(log_files)

    for r, d, f in os.walk(EXPRESS_LOG_DIR):
        for file in f:
            if file == ".keep":
                continue
            log_files.append(file)

    return(log_files)


def view_inventory(du, host_entries):
    express_inventory = build_express_inventory(du, host_entries)
    if express_inventory:
        dump_text_file(express_inventory)
    else:
        sys.stdout.write("ERROR: failed to build inventory file: {}".format(express_inventory))


def view_config(du):
    express_config = build_express_config(du)
    if express_config:
        dump_text_file(express_config)
    else:
        sys.stdout.write("ERROR: failed to build configuration file: {}".format(express_config))


def dump_database(db_file):
    if os.path.isfile(db_file):
        with open(db_file) as json_file:
            db_json = json.load(json_file)
        pprint.pprint(db_json)


def run_cmd(cmd):
    cmd_stdout = ""
    tmpfile = "/tmp/pf9.{}.tmp".format(os.getppid())
    cmd_exitcode = os.system("{} > {} 2>&1".format(cmd,tmpfile))

    # read output of command
    if os.path.isfile(tmpfile):
        try:
            fh_tmpfile = open(tmpfile, 'r')
            cmd_stdout = fh_tmpfile.readlines()
        except:
            None

    os.remove(tmpfile)
    return cmd_exitcode, cmd_stdout


def action_header(title):
    title = "  {}  ".format(title)
    sys.stdout.write("\n{}".format(title.center(MAX_WIDTH,'*')))

def display_menu1():
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("**           Platform9 Express Wizard            **\n")
    sys.stdout.write("**            -- Maintenance Menu --             **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Delete Region\n")
    sys.stdout.write("2. Delete Host\n")
    sys.stdout.write("3. Display Region Database\n")
    sys.stdout.write("4. Display Host Database\n")
    sys.stdout.write("5. View Configuration File\n")
    sys.stdout.write("6. View Inventory File\n")
    sys.stdout.write("7. View Logs\n")
    sys.stdout.write("***************************************************\n")


def display_menu0():
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("**           Platform9 Express Wizard            **\n")
    sys.stdout.write("**               -- Main Menu --                 **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Discover/Add Regions\n")
    sys.stdout.write("2. Discover/Add Hosts\n")
    sys.stdout.write("3. Discover/Add Clusters\n")
    sys.stdout.write("4. Show Region\n")
    sys.stdout.write("5. Onboard Host to Region\n")
    sys.stdout.write("6. Maintenance\n")
    sys.stdout.write("***************************************************\n")


def menu_level1():
    user_input = ""
    while not user_input in ['q','Q']:
        display_menu1()
        user_input = user_io.read_kbd("Enter Selection", [], '', True, True)
        if user_input == '1':
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    delete_du(selected_du)
        elif user_input == '2':
            sys.stdout.write("\nNot Implemented\n")
        elif user_input == '3':
            dump_database(CONFIG_FILE)
        elif user_input == '4':
            dump_database(HOST_FILE)
        elif user_input == '5':
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    new_host = view_config(selected_du)
        elif user_input == '6':
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    host_entries = get_hosts(selected_du['url'])
                    new_host = view_inventory(selected_du, host_entries)
        elif user_input == '7':
            log_files = get_logs()
            if len(log_files) == 0:
                sys.stdout.write("\nNo Logs Found")
            else:
                view_log(log_files)
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")
        sys.stdout.write("\n")


def menu_level0():
    user_input = ""
    while not user_input in ['q','Q']:
        display_menu0()
        user_input = user_io.read_kbd("Enter Selection", [], '', True, True)
        if user_input == '1':
            action_header("MANAGE REGIONS")
            selected_du = add_edit_du()
            if selected_du != None:
                if selected_du == "define-new-du":
                    target_du = None
                else:
                    target_du = selected_du
                new_du_list = add_region(target_du)
                if new_du_list:
                    reports.report_du_info(new_du_list,CONFIG_FILE,HOST_FILE)
        elif user_input == '2':
            action_header("MANAGE HOSTS")
            sys.stdout.write("\nSelect Region to add Host to:")
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    flag_more_hosts = True
                    while flag_more_hosts:
                        new_host = add_host(selected_du)
                        user_input = user_io.read_kbd("\nAdd Another Host?", ['y','n'], 'n', True, True)
                        if user_input == "n":
                            flag_more_hosts = False
        elif user_input == '3':
            action_header("MANAGE CLUSTERS")
            sys.stdout.write("\nSelect Region to add Cluster to:")
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    new_cluster = add_cluster(selected_du)
        elif user_input == '4':
            action_header("SHOW REGION")
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    du_entries = get_configs(selected_du['url'])
                    reports.report_du_info(du_entries,CONFIG_FILE,HOST_FILE)
                    host_entries = get_hosts(selected_du['url'])
                    reports.report_host_info(host_entries,HOST_FILE,CONFIG_FILE)
                    if selected_du['du_type'] in ['Kubernetes','KVM/Kubernetes']:
                        cluster_entries = datamodel.get_clusters(selected_du['url'],CLUSTER_FILE)
                        reports.report_cluster_info(cluster_entries,CLUSTER_FILE)
        elif user_input == '5':
            action_header("ONBOARD HOSTS")
            selected_du = select_du()
            if selected_du:
                if selected_du != "q":
                    host_entries = get_hosts(selected_du['url'])
                    run_express(selected_du, host_entries)
        elif user_input == '6':
            menu_level1()
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")

        if user_input != '7':
            sys.stdout.write("\n")


## main
args = _parse_args()

# globals
HOME_DIR = expanduser("~")
CONFIG_DIR = "{}/.pf9-wizard".format(HOME_DIR)
CONFIG_FILE = "{}/du.conf".format(CONFIG_DIR)
HOST_FILE = "{}/hosts.conf".format(CONFIG_DIR)
CLUSTER_FILE = "{}/clusters.conf".format(CONFIG_DIR)
EXPRESS_REPO = "https://github.com/platform9/express.git"
EXPRESS_INSTALL_DIR = "{}/.pf9-wizard/pf9-express".format(HOME_DIR)
EXPRESS_LOG_DIR = "{}/.pf9-wizard/pf9-express/log".format(HOME_DIR)
PF9_EXPRESS = "{}/.pf9-wizard/pf9-express/pf9-express".format(HOME_DIR)
MAX_WIDTH = 132

# perform initialization (if invoked with '--init')
if args.init:
    sys.stdout.write("INFO: initializing configuration\n")
    if os.path.isfile(HOST_FILE):
        os.remove(HOST_FILE)
    if os.path.isfile(CONFIG_FILE):
        os.remove(CONFIG_FILE)
    if os.path.isfile(CLUSTER_FILE):
        os.remove(CLUSTER_FILE)

# main menu loop
menu_level0()

# exit cleanly
sys.exit(0)
