import os
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


