import os
import sys
import json
import globals
import ssh_utils

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
        'sub_if_config': "",
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


def create_bond_entry():
    bond_record = {
        'bond_name': "",
        'bond_ifname': "",
        'bond_mode': "",
        'bond_mtu': "",
        'bond_members': []
    }
    return(bond_record)


def create_host_profile():
    profile_record = {
        'auth_type': "",
        'auth_ssh_key': "",
        'auth_password': "",
        'auth_username': ""
    }
    return(profile_record)


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


def import_region(import_file_path):
    sys.stdout.write("Importing Region (existing data will be over-written) from import file: {}\n".format(import_file_path))

    if not os.path.isfile(import_file_path):
        sys.stdout.write("--> failed to open import file: {}\n".format(import_file_path))
        return(None)

    with open(import_file_path) as json_file:
        region_config = json.load(json_file)

    required_keys = ['region','hosts','clusters']
    for k in required_keys:
        if not k in region_config:
            sys.stdout.write("--> export data missing dictionary key: {}\n".format(k))

    sys.stdout.write("--> importing region configuration\n")
    write_config(region_config['region'])

    sys.stdout.write("--> importing hosts\n")
    for h in region_config['hosts']:
        sys.stdout.write("    {}\n".format(h['hostname']))
        write_host(h)

    sys.stdout.write("--> importing clusters\n")
    for c in region_config['clusters']:
        sys.stdout.write("    {}\n".format(c['name']))
        write_cluster(c)


def export_region(du_urls):
    du_url = du_urls[0]
    if not du_url.startswith('https://'):
        target_du = "https://{}".format(du_url)
    else:
        target_du = du_url

    # get region
    du = get_du_metadata(target_du)
    if not du:
        sys.stdout.write("--> ERROR: region not found\n")
        return(None)

    # get hosts and clusters
    du_hosts = get_hosts(target_du)
    du_clusters = get_clusters(target_du)

    # create export
    region_export = {}
    region_export['region'] = du
    region_export['hosts'] = []
    region_export['clusters'] = []
    for h in du_hosts:
        region_export['hosts'].append(h)
    for c in du_clusters:
        region_export['clusters'].append(c)

    export_file = "/tmp/{}.json".format(du_url.replace('https://',''))
    try:
        with open(export_file, 'w') as outfile:
            json.dump(region_export, outfile)
    except:
        sys.stdout.write("ERROR: failed to write export file: {}".format(export_file))
        return(None)
    
    sys.stdout.write("Export complete: {}\n".format(export_file))


def get_du_metadata(du_url):
    du_config = {}
    if os.path.isfile(globals.CONFIG_FILE):
        with open(globals.CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)
        for du in du_configs:
            if du['url'] == du_url:
                du_config = dict(du)
                break

    return(du_config)


def get_defined_hosts(du_url):
    num_discovered_hosts = 0

    if os.path.isfile(globals.HOST_FILE):
        with open(globals.HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] == du_url:
                num_discovered_hosts += 1

    return(num_discovered_hosts)


def get_cluster_record(du_url,cluster_name):
    cluster_metadata = {}
    if os.path.isfile(globals.CLUSTER_FILE):
        with open(globals.CLUSTER_FILE) as json_file:
            cluster_configs = json.load(json_file)
        for cluster in cluster_configs:
            if cluster['du_url'] == du_url and cluster['name'] == cluster_name:
                cluster_metadata = dict(cluster)
                break

    return(cluster_metadata)


def get_host_record(du_url,hostname):
    host_metadata = {}
    if os.path.isfile(globals.HOST_FILE):
        with open(globals.HOST_FILE) as json_file:
            host_configs = json.load(json_file)
        for host in host_configs:
            if host['du_url'] == du_url and host['hostname'] == hostname:
                host_metadata = dict(host)
                break

    return(host_metadata)


def get_unattached_masters(cluster):
    masters = []
    if os.path.isfile(globals.HOST_FILE):
        with open(globals.HOST_FILE) as json_file:
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


def get_unattached_workers(cluster):
    workers = []
    if os.path.isfile(globals.HOST_FILE):
        with open(globals.HOST_FILE) as json_file:
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


def get_clusters(du_url):
    du_clusters = []
    if os.path.isfile(globals.CLUSTER_FILE):
        with open(globals.CLUSTER_FILE) as json_file:
            du_clusters = json.load(json_file)

    if du_url == None:
        filtered_clusters = list(du_clusters)
    else:
        filtered_clusters = []
        for cluster in du_clusters:
            if cluster['du_url'] == du_url:
                filtered_clusters.append(cluster)

    return(filtered_clusters)


def get_configs(du_url=None):
    du_configs = []
    if os.path.isfile(globals.CONFIG_FILE):
        with open(globals.CONFIG_FILE) as json_file:
            tmp_du_configs = json.load(json_file)
            for tmp_du in tmp_du_configs:
                du_configs.append(tmp_du)

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
    if os.path.isfile(globals.CONFIG_FILE):
        with open(globals.CONFIG_FILE) as json_file:
            du_configs = json.load(json_file)
        for du in du_configs:
            if du['url'] == target_du['url']:
                sys.stdout.write("--> found target Region\n")
            else:
                new_du_list.append(du)
    else:
        sys.stdout.write("\nERROR: failed to open Region database: {}".format(globals.CONFIG_FILE))

    # update DU database
    try:
        with open(globals.CONFIG_FILE, 'w') as outfile:
            json.dump(new_du_list, outfile)
    except:
        sys.stdout.write("\nERROR: failed to update Region database: {}".format(globals.CONFIG_FILE))


def get_hosts(du_url):
    du_hosts = []
    if os.path.isfile(globals.HOST_FILE):
        with open(globals.HOST_FILE) as json_file:
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
    if not os.path.isdir(globals.CONFIG_DIR):
        try:
            os.mkdir(globals.CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(globals.CONFIG_DIR))

    current_clusters = get_clusters(None)
    if len(current_clusters) == 0:
        current_clusters.append(cluster)
        with open(globals.CLUSTER_FILE, 'w') as outfile:
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
        with open(globals.CLUSTER_FILE, 'w') as outfile:
            json.dump(update_clusters, outfile)


def write_host(host):
    if not os.path.isdir(globals.CONFIG_DIR):
        try:
            os.mkdir(globals.CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(globals.CONFIG_DIR))

    # get all hosts
    current_hosts = get_hosts(None)
    if len(current_hosts) == 0:
        current_hosts.append(host)
        with open(globals.HOST_FILE, 'w') as outfile:
            json.dump(current_hosts, outfile)
    else:
        update_hosts = []
        flag_found = False
        for h in current_hosts:
            if h['hostname'] == host['hostname'] and h['uuid'] == host['uuid']:
                update_hosts.append(host)
                flag_found = True
            elif h['hostname'] == host['hostname'] and h['ip'] == host['ip'] and h['du_url'] == host['du_url']:
                update_hosts.append(host)
                flag_found = True
            else:
                update_hosts.append(h)
        if not flag_found:
            update_hosts.append(host)
        with open(globals.HOST_FILE, 'w') as outfile:
            json.dump(update_hosts, outfile)


def write_config(du):
    """Write config to disk"""
    # read du database
    if not os.path.isdir(globals.CONFIG_DIR):
        try:
            os.mkdir(globals.CONFIG_DIR)
        except:
            fail("failed to create directory: {}".format(globals.CONFIG_DIR))

    current_config = get_configs()
    if len(current_config) == 0:
        current_config.append(du)
        with open(globals.CONFIG_FILE, 'w') as outfile:
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
        with open(globals.CONFIG_FILE, 'w') as outfile:
            json.dump(update_config, outfile)


def cluster_in_array(target_url,target_name,target_clusters):
    for cluster in target_clusters:
        if cluster['du_url'] == target_url and cluster['name'] == target_name:
            return(True)
    return(False)


def get_cluster_uuid(du_url, cluster_name):
    cluster_settings = get_cluster_record(du_url, cluster_name)
    if cluster_settings:
        return(cluster_settings['uuid'])
    return(None)

