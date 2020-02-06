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
        'cluster_uuid': "",
        'fk_auth_profile': ""
    }
    return(host_record)


def create_bond_profile_entry():
    bond_profile = {
        'bond_name': "",
        'bond_ifname': "",
        'bond_mode': "",
        'bond_mtu': "",
        'bond_members': []
    }
    return(bond_profile)


def create_auth_profile_entry():
    auth_profile = {
        'auth_name': "",
        'auth_type': "",
        'auth_ssh_key': "",
        'auth_password': "",
        'auth_username': ""
    }
    return(auth_profile)


def create_role_profile_entry():
    role_profile = {
        'role_name': "",
        'pf9-kube': "",
        'nova': "",
        'glance': "",
        'cinder': "",
        'designate': "",
        'node_type': "",
    }
    return(role_profile)


def create_host_profile_entry():
    host_profile = {
        'host_profile_name': "",
        'fk_auth_profile': "",
        'fk_bond_profile': "",
        'fk_role_profile': ""
    }
    return(host_profile)


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

    # for host imports, enforce a minimum set of required keys
    host_record_required_keys = ["du_url", "du_type", "ip", "du_host_type", "hostname"]

    if not os.path.isfile(import_file_path):
        sys.stdout.write("--> failed to open import file: {}\n".format(import_file_path))
        return(None)

    with open(import_file_path) as json_file:
        region_config = json.load(json_file)

    required_keys = ['region','hosts','clusters','auth-profiles','bond-profiles','role-profiles','host-profiles']
    for key_name in required_keys:
        if not key_name in region_config:
            sys.stdout.write("--> INFO: export data missing dictionary key: {}\n".format(key_name))
            continue

        if key_name == "region":
            sys.stdout.write("--> importing region\n")
            write_config(region_config['region'])
        elif key_name == "hosts":
            sys.stdout.write("--> importing hosts\n")
            for target in region_config['hosts']:
                sys.stdout.write("    {}\n".format(target['hostname']))
                host_record = create_host_entry()
                for req_key in host_record_required_keys:
                    if not req_key in target:
                        sys.stdout.write("FATAL: missing required key: {}\n".format(req_key))
                        sys.exit(0)
                    host_record[req_key] = target[req_key]
                write_host(host_record)
        elif key_name == "clusters":
            sys.stdout.write("--> importing clusters\n")
            for target in region_config['clusters']:
                sys.stdout.write("    {}\n".format(target['name']))
                write_cluster(target)
        elif key_name == "auth-profiles":
            sys.stdout.write("--> importing auth-profiles\n")
            for target in region_config['auth-profiles']:
                sys.stdout.write("    {}\n".format(target['auth_name']))
                write_auth_profile(target)
        elif key_name == "bond-profiles":
            sys.stdout.write("--> importing bond-profiles\n")
            for target in region_config['bond-profiles']:
                sys.stdout.write("    {}\n".format(target['bond_name']))
                write_bond_profile(target)
        elif key_name == "role-profiles":
            sys.stdout.write("--> importing role-profiles\n")
            for target in region_config['role-profiles']:
                sys.stdout.write("    {}\n".format(target['role_name']))
                write_role_profile(target)
        elif key_name == "host-profiles":
            sys.stdout.write("--> importing host-profiles\n")
            for target in region_config['host-profiles']:
                sys.stdout.write("    {}\n".format(target['host_profile_name']))
                write_host_profile(target)


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
    du_auth_profiles = get_auth_profiles()
    du_bond_profiles = get_bond_profiles()
    du_role_profiles = get_role_profiles()
    du_host_profiles = get_host_profiles()

    # create export
    region_export = {}
    region_export['region'] = du
    region_export['hosts'] = []
    region_export['clusters'] = []
    region_export['auth-profiles'] = []
    region_export['bond-profiles'] = []
    region_export['role-profiles'] = []
    region_export['host-profiles'] = []
    for target in du_hosts:
        region_export['hosts'].append(target)
    for target in du_clusters:
        region_export['clusters'].append(target)
    for target in du_auth_profiles:
        region_export['auth-profiles'].append(target)
    for target in du_bond_profiles:
        region_export['bond-profiles'].append(target)
    for target in du_role_profiles:
        region_export['role-profiles'].append(target)
    for target in du_host_profiles:
        region_export['host-profiles'].append(target)

    export_file = "/tmp/{}.json".format(du_url.replace('https://',''))
    try:
        with open(export_file, 'w') as outfile:
            json.dump(region_export, outfile)
    except:
        sys.stdout.write("ERROR: failed to write export file: {}".format(export_file))
        return(None)
    
    sys.stdout.write("Export complete: {}\n".format(export_file))


def get_host_profile_metadata(host_profile_name):
    host_profile_config = {}
    if os.path.isfile(globals.HOST_PROFILE_FILE):
        with open(globals.HOST_PROFILE_FILE) as json_file:
            host_profile_configs = json.load(json_file)
        for profile in host_profile_configs:
            if profile['host_profile_name'] == host_profile_name:
                host_profile_config = dict(profile)
                break

    return(host_profile_config)


def get_bond_profile_metadata(bond_profile_name):
    bond_config = {}
    if os.path.isfile(globals.BOND_PROFILE_FILE):
        with open(globals.BOND_PROFILE_FILE) as json_file:
            bond_configs = json.load(json_file)
        for bond in bond_configs:
            if bond['bond_name'] == bond_profile_name:
                bond_config = dict(bond)
                break

    return(bond_config)


def get_role_profile_metadata(role_profile_name):
    role_config = {}
    if os.path.isfile(globals.ROLE_PROFILE_FILE):
        with open(globals.ROLE_PROFILE_FILE) as json_file:
            role_configs = json.load(json_file)
        for role in role_configs:
            if role['role_name'] == role_profile_name:
                role_config = dict(role)
                break

    return(role_config)


def get_auth_profile_metadata(auth_profile_name):
    auth_config = {}
    if os.path.isfile(globals.AUTH_PROFILE_FILE):
        with open(globals.AUTH_PROFILE_FILE) as json_file:
            auth_configs = json.load(json_file)
        for auth in auth_configs:
            if auth['auth_name'] == auth_profile_name:
                auth_config = dict(auth)
                break

    return(auth_config)


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


def get_host_profiles():
    host_profile_configs = []
    if os.path.isfile(globals.HOST_PROFILE_FILE):
        with open(globals.HOST_PROFILE_FILE) as json_file:
            tmp_host_profiles = json.load(json_file)
            for tmp_host in tmp_host_profiles:
                host_profile_configs.append(tmp_host)

    return(host_profile_configs)


def get_bond_profiles():
    bond_configs = []
    if os.path.isfile(globals.BOND_PROFILE_FILE):
        with open(globals.BOND_PROFILE_FILE) as json_file:
            tmp_bond_configs = json.load(json_file)
            for tmp_auth in tmp_bond_configs:
                bond_configs.append(tmp_auth)

    return(bond_configs)


def get_role_profiles():
    role_configs = []
    if os.path.isfile(globals.ROLE_PROFILE_FILE):
        with open(globals.ROLE_PROFILE_FILE) as json_file:
            tmp_role_configs = json.load(json_file)
            for tmp_role in tmp_role_configs:
                role_configs.append(tmp_role)

    return(role_configs)

def get_auth_profiles():
    auth_configs = []
    if os.path.isfile(globals.AUTH_PROFILE_FILE):
        with open(globals.AUTH_PROFILE_FILE) as json_file:
            tmp_auth_configs = json.load(json_file)
            for tmp_auth in tmp_auth_configs:
                auth_configs.append(tmp_auth)

    return(auth_configs)


def get_role_profile_names():
    role_profile_names = []
    if os.path.isfile(globals.ROLE_PROFILE_FILE):
        with open(globals.ROLE_PROFILE_FILE) as json_file:
            tmp_role_configs = json.load(json_file)
            for tmp_role in tmp_role_configs:
                role_profile_names.append(tmp_role['role_name'])

    return(role_profile_names)


def get_host_profile_names():
    host_profile_names = []
    if os.path.isfile(globals.HOST_PROFILE_FILE):
        with open(globals.HOST_PROFILE_FILE) as json_file:
            tmp_host_profile_configs = json.load(json_file)
            for tmp_host_profile in tmp_host_profile_configs:
                host_profile_names.append(tmp_host_profile['host_profile_name'])

    return(host_profile_names)


def get_auth_profile_names():
    auth_profile_names = []
    if os.path.isfile(globals.AUTH_PROFILE_FILE):
        with open(globals.AUTH_PROFILE_FILE) as json_file:
            tmp_auth_configs = json.load(json_file)
            for tmp_auth in tmp_auth_configs:
                auth_profile_names.append(tmp_auth['auth_name'])

    return(auth_profile_names)


def get_bond_profile_names():
    bond_profile_names = []
    if os.path.isfile(globals.BOND_PROFILE_FILE):
        with open(globals.BOND_PROFILE_FILE) as json_file:
            tmp_configs = json.load(json_file)
            for tmp_auth in tmp_configs:
                bond_profile_names.append(tmp_auth['bond_name'])

    return(bond_profile_names)


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


def write_host_profile(host_profile):
    """Write Host Profile file to disk"""
    current_host_profile = get_host_profiles()
    if len(current_host_profile) == 0:
        current_host_profile.append(host_profile)
        with open(globals.HOST_PROFILE_FILE, 'w') as outfile:
            json.dump(current_host_profile, outfile)
    else:
        update_profile = []
        flag_found = False
        for profile in current_host_profile:
            if profile['host_profile_name'] == host_profile['host_profile_name']:
                update_profile.append(host_profile)
                flag_found = True
            else:
                update_profile.append(profile)
        if not flag_found:
            update_profile.append(host_profile)
        with open(globals.HOST_PROFILE_FILE, 'w') as outfile:
            json.dump(update_profile, outfile)


def write_bond_profile(bond):
    """Write bond file to disk"""
    current_bond = get_bond_profiles()
    if len(current_bond) == 0:
        current_bond.append(bond)
        with open(globals.BOND_PROFILE_FILE, 'w') as outfile:
            json.dump(current_bond, outfile)
    else:
        update_profile = []
        flag_found = False
        for profile in current_bond:
            if profile['bond_name'] == bond['bond_name']:
                update_profile.append(bond)
                flag_found = True
            else:
                update_profile.append(profile)
        if not flag_found:
            update_profile.append(bond)
        with open(globals.BOND_PROFILE_FILE, 'w') as outfile:
            json.dump(update_profile, outfile)


def write_role_profile(role):
    """Write role file to disk"""
    current_role = get_role_profiles()
    if len(current_role) == 0:
        current_role.append(role)
        with open(globals.ROLE_PROFILE_FILE, 'w') as outfile:
            json.dump(current_role, outfile)
    else:
        update_role = []
        flag_found = False
        for target_role in current_role:
            if target_role['role_name'] == role['role_name']:
                update_role.append(role)
                flag_found = True
            else:
                update_role.append(target_role)
        if not flag_found:
            update_role.append(role)
        with open(globals.ROLE_PROFILE_FILE, 'w') as outfile:
            json.dump(update_role, outfile)


def write_auth_profile(auth):
    """Write authorization file to disk"""
    current_profile = get_auth_profiles()
    if len(current_profile) == 0:
        current_profile.append(auth)
        with open(globals.AUTH_PROFILE_FILE, 'w') as outfile:
            json.dump(current_profile, outfile)
    else:
        update_profile = []
        flag_found = False
        for profile in current_profile:
            if profile['auth_name'] == auth['auth_name']:
                update_profile.append(auth)
                flag_found = True
            else:
                update_profile.append(profile)
        if not flag_found:
            update_profile.append(auth)
        with open(globals.AUTH_PROFILE_FILE, 'w') as outfile:
            json.dump(update_profile, outfile)


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


def get_aggregate_host_profile(host_profile_name):
    host_profile_metadata = {}

    host_profile = get_host_profile_metadata(host_profile_name)
    auth_profile = get_auth_profile_metadata(host_profile['fk_auth_profile'])
    bond_profile = get_bond_profile_metadata(host_profile['fk_bond_profile'])
    role_profile = get_role_profile_metadata(host_profile['fk_role_profile'])

    if auth_profile:
        host_profile_metadata['auth_profile'] = {}
        host_profile_metadata['auth_profile']['auth_name'] = auth_profile['auth_name']
        host_profile_metadata['auth_profile']['auth_type'] = auth_profile['auth_type']
        host_profile_metadata['auth_profile']['auth_ssh_key'] = auth_profile['auth_ssh_key']
        host_profile_metadata['auth_profile']['auth_password'] = auth_profile['auth_password']
        host_profile_metadata['auth_profile']['auth_username'] = auth_profile['auth_username']
    if bond_profile:
        host_profile_metadata['bond_profile'] = {}
        host_profile_metadata['bond_profile']['bond_name'] = bond_profile['bond_name']
        host_profile_metadata['bond_profile']['bond_ifname'] = bond_profile['bond_ifname']
        host_profile_metadata['bond_profile']['bond_mode'] = bond_profile['bond_mode']
        host_profile_metadata['bond_profile']['bond_mtu'] = bond_profile['bond_mtu']
        host_profile_metadata['bond_profile']['bond_members'] = bond_profile['bond_members']
    if role_profile:
        host_profile_metadata['role_profile'] = {}
        host_profile_metadata['role_profile']['role_name'] = role_profile['role_name']
        host_profile_metadata['role_profile']['pf9-kube'] = role_profile['pf9-kube']
        host_profile_metadata['role_profile']['nova'] = role_profile['nova']
        host_profile_metadata['role_profile']['glance'] = role_profile['glance']
        host_profile_metadata['role_profile']['cinder'] = role_profile['cinder']
        host_profile_metadata['role_profile']['designate'] = role_profile['designate']
        host_profile_metadata['role_profile']['node_type'] = role_profile['node_type']

    return(host_profile_metadata)

