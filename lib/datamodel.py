import os
import sys
import json


def create_du_entry():
    du_record = {
        'url': "",
        'du_type': "",
        'username': "",
        'password': "",
        'tenant': "",
        'git_branch': "",
        'region': "",
        'region_proxy': "-",
        'dns_list': "",
        'auth_type': "",
        'auth_ssh_key': "",
        'auth_password': "",
        'auth_username': "",
        'bond_ifname': "",
        'bond_mode': "",
        'bond_mtu': ""
    }
    return(du_record)


def create_host_entry():
    host_record = {
        'du_url': "",
        'du_type': "",
        'ip': "",
        'uuid': "",
        'ip_interfaces': "",
        'du_host_type': "",
        'hostname': "",
        'record_source': "",
        'ssh_status': "",
        'bond_config': "",
        'pf9-kube': "",
        'nova': "",
        'glance': "",
        'cinder': "",
        'designate': "",
        'node_type': "",
        'cluster_name': "",
        'cluster_attach_status': "",
        'cluster_uuid': ""
    }
    return(host_record)


def create_cluster_entry():
    cluster_record = {
        'du_url': "",
        'name': "",
        'record_source': "",
        'uuid': "",
        'containers_cidr': "",
        'services_cidr': "",
        'master_vip_ipv4': "",
        'master_vip_iface': "",
        'metallb_cidr': "",
        'privileged': "",
        'app_catalog_enabled': "",
        'allow_workloads_on_master': ""
    }
    return(cluster_record)


def get_du_metadata(du_url,CONFIG_FILE):
    du_config = {}
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)
        for du in du_configs:
            if du['url'] == du_url:
                du_config = dict(du)
                break

    return(du_config)


def get_defined_hosts(du_url,HOST_FILE):
    num_discovered_hosts = 0

    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] == du_url:
                num_discovered_hosts += 1

    return(num_discovered_hosts)


def get_cluster_record(du_url,cluster_name,CLUSTER_FILE):
    cluster_metadata = {}
    if os.path.isfile(CLUSTER_FILE):
        with open(CLUSTER_FILE) as json_file:
            cluster_configs = json.load(json_file)
        for cluster in cluster_configs:
            if cluster['du_url'] == du_url and cluster['name'] == cluster_name:
                cluster_metadata = dict(cluster)
                break

    return(cluster_metadata)


def get_host_record(du_url,hostname,HOST_FILE):
    host_metadata = {}
    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] == du_url and host['hostname'] == hostname:
                host_metadata = dict(host)
                break

    return(host_metadata)


def get_unattached_masters(cluster,HOST_FILE):
    masters = []
    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] != cluster['du_url']:
                continue
            if host['cluster_name'] != cluster['name']:
                continue
            if host['node_type'] != "master":
                continue
            if host['cluster_attach_status'] != "Attached":
                masters.append(host)
    return(masters)


def get_unattached_workers(cluster,HOST_FILE):
    workers = []
    if os.path.isfile(HOST_FILE):
        with open(HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] != cluster['du_url']:
                continue
            if host['cluster_name'] != cluster['name']:
                continue
            if host['node_type'] != "worker":
                continue
            if host['cluster_attach_status'] != "Attached":
                workers.append(host)
    return(workers)


def get_clusters(du_url,CLUSTER_FILE):
    du_clusters = []
    if os.path.isfile(CLUSTER_FILE):
        with open(CLUSTER_FILE) as json_file:
            du_clusters = json.load(json_file)

    if du_url == None:
        filtered_clusters = list(du_clusters)
    else:
        filtered_clusters = []
        for cluster in du_clusters:
            if cluster['du_url'] == du_url:
                filtered_clusters.append(cluster)

    return(filtered_clusters)


def get_configs(CONFIG_FILE,du_url=None):
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


def delete_du(target_du,CONFIG_FILE):
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


def get_hosts(du_url,HOST_FILE):
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


def write_cluster(cluster,CONFIG_DIR,CLUSTER_FILE):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_clusters = get_clusters(None,CLUSTER_FILE)
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


def write_host(host,CONFIG_DIR,HOST_FILE):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    # get all hosts
    current_hosts = get_hosts(None,HOST_FILE)
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


def write_config(du,CONFIG_DIR,CONFIG_FILE):
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.mkdir(CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(CONFIG_DIR))

    current_config = get_configs(CONFIG_FILE)
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


def cluster_in_array(target_url,target_name,target_clusters):
    for cluster in target_clusters:
        if cluster['du_url'] == target_url and cluster['name'] == target_name:
            return(True)
    return(False)


def get_cluster_uuid(du_url, cluster_name,CLUSTER_FILE):
    cluster_settings = get_cluster_record(du_url, cluster_name, CLUSTER_FILE)
    if cluster_settings:
        return(cluster_settings['uuid'])
    return(None)


