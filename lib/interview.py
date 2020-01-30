import sys
import os
import time
import globals
import io
import user_io
import datamodel
import interview
import du_utils
import ssh_utils
import resmgr_utils
import express_utils
import pmk_utils
import datamodel
from encrypt import Encryption


def get_cluster_metadata(du, project_id, token):
    if du['du_type'] in ['KVM','VMware']:
        sys.stdout.write("Invalid region type for adding cluster ({})\n".format(du['du_type']))
        return ''

    # initialize cluster record
    cluster_metadata = {}
    cluster_metadata['record_source'] = "User-Defined"
    cluster_metadata['du_url'] = du['url']
    cluster_metadata['name'] = user_io.read_kbd("--> Cluster Name", [], '', True, True)
    if cluster_metadata['name'] == "q":
        return ''

    # get current cluster settings (if already defined)
    cluster_settings = datamodel.get_cluster_record(du['url'], cluster_metadata['name'])
    if cluster_settings:
        name = cluster_settings['name']
        containers_cidr = cluster_settings['containers_cidr']
        services_cidr = cluster_settings['services_cidr']
        master_vip_ipv4 = cluster_settings['master_vip_ipv4']
        master_vip_iface = cluster_settings['master_vip_iface']
        metallb_cidr = cluster_settings['metallb_cidr']
        privileged = cluster_settings['privileged']
        app_catalog_enabled = cluster_settings['app_catalog_enabled']
        allow_workloads_on_master = cluster_settings['allow_workloads_on_master']
    else:
        containers_cidr = "192.168.0.0/16"
        services_cidr = "192.169.0.0/16"
        master_vip_ipv4 = ""
        master_vip_iface = "eth0"
        metallb_cidr = ""
        privileged = "1"
        app_catalog_enabled = "0"
        allow_workloads_on_master = "0"

    cluster_metadata['containers_cidr'] = user_io.read_kbd("--> Containers CIDR", [], containers_cidr, True, True)
    if cluster_metadata['containers_cidr'] == "q":
        return ''
    cluster_metadata['services_cidr'] = user_io.read_kbd("--> Services CIDR", [], services_cidr, True, True)
    if cluster_metadata['services_cidr'] == "q":
        return ''
    cluster_metadata['master_vip_ipv4'] = user_io.read_kbd("--> Master VIP", [], master_vip_ipv4, True, True)
    if cluster_metadata['master_vip_ipv4'] == "q":
        return ''
    cluster_metadata['master_vip_iface'] = user_io.read_kbd("--> Interface Name for VIP", [], master_vip_iface, True, True)
    if cluster_metadata['master_vip_iface'] == "q":
        return ''
    cluster_metadata['metallb_cidr'] = user_io.read_kbd("--> IP Range for MetalLB", [], metallb_cidr, True, True)
    if cluster_metadata['metallb_cidr'] == "q":
        return ''
    cluster_metadata['privileged'] = user_io.read_kbd("--> Privileged API Mode", ['0','1'], privileged, True, True)
    if cluster_metadata['privileged'] == "q":
        return ''
    cluster_metadata['app_catalog_enabled'] = user_io.read_kbd("--> Enable Helm Application Catalog", ['0','1'], app_catalog_enabled, True, True)
    if cluster_metadata['app_catalog_enabled'] == "q":
        return ''
    cluster_metadata['allow_workloads_on_master'] = user_io.read_kbd("--> Enable Workloads on Master Nodes", ['0','1'], allow_workloads_on_master, True, True)
    if cluster_metadata['allow_workloads_on_master'] == "q":
        return ''

    return(cluster_metadata)


def get_host_metadata(du, project_id, token):
    if du['du_type'] == "KVM":
        du_host_type = "kvm"
    elif du['du_type'] == "Kubernetes":
        du_host_type = "kubernetes"
    elif du['du_type'] == "VMware":
        du_host_type = "vmware"
    elif du['du_type'] == "KVM/Kubernetes":
        du_host_type = user_io.read_kbd("--> Host Type ['kvm','kubernetes']", ['kvm','kubernetes'], 'kvm', True, True)
        if du_host_type == "q":
            return ''

    # initialize host record
    host_metadata = datamodel.create_host_entry()
    host_metadata['record_source'] = "User-Defined"
    host_metadata['du_host_type'] = du_host_type
    host_metadata['hostname'] = user_io.read_kbd("--> Hostname", [], '', True, True)
    if host_metadata['hostname'] == "q":
        return ''

    # get current host settings (if already defined)
    host_settings = datamodel.get_host_record(du['url'], host_metadata['hostname'])
    if host_settings:
        host_ip = host_settings['ip']
        host_ip_interfaces = host_settings['ip_interfaces']
        host_sub_if_config = host_settings['sub_if_config']
        host_nova = host_settings['nova']
        host_glance = host_settings['glance']
        host_cinder = host_settings['cinder']
        host_designate = host_settings['designate']
        host_node_type = host_settings['node_type']
        host_pf9_kube = host_settings['pf9-kube']
        host_cluster_name = host_settings['cluster_name']
        host_metadata['ip_interfaces'] = host_settings['ip_interfaces']
        host_metadata['uuid'] = host_settings['uuid']
    else:
        host_ip = ""
        host_sub_if_config = ""
        host_nova = "y"
        host_glance = "n"
        host_cinder = "n"
        host_designate = "n"
        host_node_type = ""
        host_pf9_kube = "n"
        host_cluster_name = "Unassigned"
        host_metadata['ip_interfaces'] = ""
        host_metadata['uuid'] = ""

    host_metadata['ip'] = user_io.read_kbd("--> Primary IP Address", [], host_ip, True, True)
    if host_metadata['ip'] == "q":
        return ''

    # prompt for host profile
    # host_profiles = datamodel.filter_host_profiles()
    # print("---- host_profiles ---------------------------------")
    # print(host_profiles)
    # print("----------------------------------------------------")

    # prompt for KVM-specific settings
    if du_host_type == "kvm":
        host_metadata['sub_if_config'] = user_io.read_kbd("--> Sub-Interfaces", [], host_sub_if_config, True, False)
        if host_metadata['sub_if_config'] == "q":
            return ''
        host_metadata['nova'] = user_io.read_kbd("--> Enable Nova", ['y', 'n'], host_nova, True, True)
        if host_metadata['nova'] == "q":
            return ''
        host_metadata['glance'] = user_io.read_kbd("--> Enable Glance", ['y', 'n'], host_glance, True, True)
        if host_metadata['glance'] == "q":
            return ''
        host_metadata['cinder'] = user_io.read_kbd("--> Enable Cinder", ['y', 'n'], host_cinder, True, True)
        if host_metadata['cinder'] == "q":
            return ''
        host_metadata['designate'] = user_io.read_kbd("--> Enable Designate",
                                                      ['y', 'n'],
                                                      host_designate,
                                                      True, True)
        if host_metadata['designate'] == "q":
            return ''
        host_metadata['node_type'] = ""
        host_metadata['pf9-kube'] = "n"
        host_metadata['cluster_name'] = ""
    elif du_host_type == "kubernetes":
        host_metadata['sub_if_config'] = ""
        host_metadata['nova'] = ""
        host_metadata['glance'] = ""
        host_metadata['cinder'] = ""
        host_metadata['designate'] = ""
        host_metadata['pf9-kube'] = "y"

        # prompt for KVM-specific settings
        host_metadata['node_type'] = user_io.read_kbd("--> Node Type [master, worker]",
                                                      ['master', 'worker'],
                                                      host_node_type,
                                                      True, True)
        if host_metadata['node_type'] == "q":
            return ''
        host_metadata['cluster_name'] = interview.select_cluster(du['url'], host_cluster_name)
        if host_metadata['cluster_name'] == "q":
            return ''
    elif du_host_type == "vmware":
        sys.stdout.write("INFO: vmware host detected\n")

    return(host_metadata)


def select_cluster(du_url, current_assigned_cluster):
    selected_cluster = "Unassigned"
    if not os.path.isdir(globals.CONFIG_DIR):
        return(selected_cluster)
    elif not os.path.isfile(globals.CLUSTER_FILE):
        return(selected_cluster)
    else:
        defined_clusters = datamodel.get_clusters(du_url)
        if len(defined_clusters) == 0:
            return(selected_cluster)
        else:
            cnt = 1
            allowed_values = ['q','n']
            sys.stdout.write("    Available Clusters:\n")
            for cluster in defined_clusters:
                if cluster['name'] == current_assigned_cluster:
                    current_assigned_cluster = cnt
                sys.stdout.write("    {}. {}\n".format(cnt, cluster['name']))
                allowed_values.append(str(cnt))
                cnt += 1

            # manage unassigned option
            if current_assigned_cluster == "Unassigned":
                current_assigned_cluster = cnt
            allowed_values.append(str(cnt))
            sys.stdout.write("    {}. Unassigned\n".format(cnt))

            user_input = user_io.read_kbd("--> Select Cluster",
                                          allowed_values,
                                          current_assigned_cluster,
                                          True, True)
            if user_input == "q":
                return(selected_cluster)
            else:
                if sys.version_info[0] == 2:
                    idx = int(user_input)
                else:
                    idx = int(user_input)

                if (int(user_input)) == cnt:
                    return(selected_cluster)
                idx = int(user_input) - 1
                selected_cluster = defined_clusters[idx]['name']

        return(selected_cluster)


def get_host_profile_settings(target_host_profile):
    # initialize host profile data structure
    host_profile_metadata = datamodel.create_host_profile_entry()

    if target_host_profile == None:
        host_profile_name = user_io.read_kbd("--> Profile Name", [], '', True, True)
        if host_profile_name == 'q':
            return ''
    else:
        host_profile_name = target_host_profile
    
    target_host_profile_metadata = datamodel.get_host_profile_metadata(host_profile_name)
    try:
        fk_auth_profile = target_host_profile_metadata['fk_auth_profile']
        fk_bond_profile = target_host_profile_metadata['fk_bond_profile']
    except:
        fk_auth_profile = ""
        fk_bond_profile = ""

    host_profile_metadata['host_profile_name'] = host_profile_name

    # prompt for auth profile
    sys.stdout.write("\nAuthorization Profiles:\n")
    auth_profile_list = datamodel.get_auth_profile_names()
    cnt = 1
    allowed_values = ['q']
    for target in auth_profile_list:
        sys.stdout.write("    {}. {}\n".format(cnt, target))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("--> Select Profile", allowed_values, fk_auth_profile, True, True)
    if user_input == 'q':
        return ''
    else:
        if type(user_input) is int or user_input.isdigit():
            host_profile_metadata['fk_auth_profile'] = auth_profile_list[int(user_input)-1]
        else:
            host_profile_metadata['fk_auth_profile'] = auth_profile_list[user_input]

    # prompt for bond profile
    sys.stdout.write("\nBond Profiles:\n")
    bond_profile_list = datamodel.get_bond_profile_names()
    cnt = 1
    allowed_values = ['q']
    for target in bond_profile_list:
        sys.stdout.write("    {}. {}\n".format(cnt, target))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("--> Select Profile", allowed_values, fk_bond_profile, True, True)
    if user_input == 'q':
        return ''
    else:
        if type(user_input) is int or user_input.isdigit():
            host_profile_metadata['fk_bond_profile'] = bond_profile_list[int(user_input)-1]
        else:
            host_profile_metadata['fk_bond_profile'] = bond_profile_list[user_input]

    return(host_profile_metadata)


def get_bond_settings(existing_bond_profile):
    # initialize bond data structure
    bond_metadata = datamodel.create_bond_profile_entry()

    if existing_bond_profile == None:
        bond_profile_name = user_io.read_kbd("--> Profile Name", [], '', True, True)
        if bond_profile_name == 'q':
            return ''
    else:
        bond_profile_name = existing_bond_profile
    
    target_bond_metadata = datamodel.get_bond_profile_metadata(bond_profile_name)
    try:
        bond_name = target_bond_metadata['bond_name']
        bond_ifname = target_bond_metadata['bond_ifname']
        bond_mode = target_bond_metadata['bond_mode']
        bond_mtu = target_bond_metadata['bond_mtu']
        bond_members = target_bond_metadata['bond_members']
    except:
        bond_name = ""
        bond_ifname = ""
        bond_mode = ""
        bond_mtu = ""
        bond_members = ""

    bond_metadata['bond_name'] = bond_profile_name
    bond_metadata['bond_ifname'] = user_io.read_kbd("--> Interface Name for Bond", [], bond_ifname, True, True)
    if bond_metadata['bond_ifname'] == 'q':
        return ''

    # prompt for bond mode
    cnt = 1
    allowed_values = ['q']
    for target_mode in globals.bond_modes:
        sys.stdout.write("    {}. {}\n".format(cnt, target_mode))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("--> Bond Mode", allowed_values, bond_mode, True, True)
    if user_input == 'q':
        return ''
    else:
        if type(user_input) is int or user_input.isdigit():
            bond_metadata['bond_mode'] = int(user_input) - 1
        else:
            bond_metadata['bond_mode'] = user_input

    bond_metadata['bond_mtu'] = user_io.read_kbd("--> MTU for Bond Interface", [], bond_mtu, True, True)
    if bond_metadata['bond_mtu'] == 'q':
        return ''

    bond_metadata['bond_members'] = user_io.read_kbd("--> Member Interfaces (space-delimitted)", [], bond_members, True, True)
    if bond_metadata['bond_members'] == 'q':
        return ''

    return(bond_metadata)


def get_auth_settings(existing_auth_profile):
    # initialize auth data structure
    auth_metadata = datamodel.create_auth_profile_entry()

    # initialize encryption
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)

    if existing_auth_profile == None:
        auth_profile_name = user_io.read_kbd("--> Profile Name", [], '', True, True)
        if auth_profile_name == 'q':
            return ''
    else:
        auth_profile_name = existing_auth_profile
    
    target_auth_metadata = datamodel.get_auth_profile_metadata(auth_profile_name)
    try:
        auth_name = target_auth_metadata['auth_name']
        auth_type = target_auth_metadata['auth_type']
        auth_ssh_key = target_auth_metadata['auth_ssh_key']
        auth_password = target_auth_metadata['auth_password']
        auth_username = target_auth_metadata['auth_username']
    except:
        auth_name = ""
        auth_type = ""
        auth_ssh_key = ""
        auth_username = ""
        auth_password = ""

    auth_metadata['auth_name'] = auth_profile_name
    auth_metadata['auth_type'] = user_io.read_kbd("--> Authentication Type ['simple', 'sshkey']", ['simple', 'sshkey'], auth_type, True, True)
    if auth_metadata['auth_type'] == 'q':
        return ''

    auth_metadata['auth_username'] = user_io.read_kbd("--> Username for Remote Host Access", [], auth_username, True, True)
    if auth_metadata['auth_username'] == 'q':
        return ''

    if auth_metadata['auth_type'] == "simple":
        auth_metadata['auth_password'] = user_io.read_kbd("--> Password for Remote Host Access", [], auth_password, False, True)
        if auth_metadata['auth_password'] == 'q':
            return ''
        else:
            auth_metadata['auth_password'] = encryption.encrypt_password(auth_metadata['auth_password'])
    else:
        auth_metadata['auth_password'] = ""

    if auth_metadata['auth_type'] == "sshkey":
        auth_metadata['auth_ssh_key'] = user_io.read_kbd("--> SSH Key for Remote Host Access", [], auth_ssh_key, True, True)
        if auth_metadata['auth_ssh_key'] == 'q':
            return ''
    else:
        auth_metadata['auth_ssh_key'] = ""

    return(auth_metadata)


def get_du_creds(existing_du_url):
    # initialize du data structure
    du_metadata = datamodel.create_du_entry()

    # initialize encryption
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)

    if existing_du_url == None:
        user_url = user_io.read_kbd("--> Region URL", [], '', True, True)
        if user_url == 'q':
            return ''
    else:
        user_url = existing_du_url
    
    if user_url.startswith('http://'):
        user_url = user_url.replace('http://', 'https://')
    if not user_url.startswith('https://'):
        user_url = "https://{}".format(user_url)

    du_metadata['du_url'] = user_url
    du_settings = datamodel.get_du_metadata(du_metadata['du_url'])
    # define du types
    du_types = [
        'KVM',
        'Kubernetes',
        'KVM/Kubernetes',
        'VMware'
    ]

    try:
        selected_du_type = du_settings['du_type']
        du_user = du_settings['username']
        du_password = encryption.decrypt_password(du_settings['password'])
        du_tenant = du_settings['tenant']
        git_branch = du_settings['git_branch']
        region_name = du_settings['region']
        region_proxy = du_settings['region_proxy']
        region_dns = du_settings['dns_list']
        region_auth_type = du_settings['auth_type']
        auth_ssh_key = du_settings['auth_ssh_key']
        auth_username = du_settings['auth_username']
        auth_password = du_settings['auth_password']
        region_bond_if_name = du_settings['bond_ifname']
        region_bond_mode = du_settings['bond_mode']
        region_bond_mtu = du_settings['bond_mtu']
    except:
        selected_du_type = ""
        du_user = ""
        du_tenant = "service"
        du_password = ""
        git_branch = "master"
        region_name = ""
        region_proxy = "-"
        region_dns = "8.8.8.8,8.8.4.4"
        region_auth_type = "sshkey"
        auth_ssh_key = "~/.ssh/id_rsa"
        auth_password = ""
        auth_username = "centos"
        region_bond_if_name = "bond0"
        region_bond_mode = "1"
        region_bond_mtu = "9000"

    # prompt for du type
    cnt = 1
    allowed_values = ['q']
    for target_type in du_types:
        sys.stdout.write("    {}. {}\n".format(cnt, target_type))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("--> Region Type", allowed_values, selected_du_type, True, True)
    if user_input == 'q':
        return ''
    else:
        if type(user_input) is int or user_input.isdigit():
            if int(user_input) > 0 and int(user_input) -1 in range(-len(du_types), len(du_types)):
                selected_du_type = du_types[int(user_input) - 1]
        else:
            for du in du_types:
                if user_input.upper() == du.upper():
                    selected_du_type = du

    # set du type
    du_metadata['du_type'] = selected_du_type
    du_metadata['region_name'] = ""

    # get common du parameters
    du_metadata['du_user'] = user_io.read_kbd("--> Region Username", [], du_user, True, True)
    if du_metadata['du_user'] == 'q':
        return ''
    du_metadata['du_password'] = user_io.read_kbd("--> Region Password", [], du_password, False, True)
    if du_metadata['du_password'] == 'q':
        return ''
    else:
        du_metadata['du_password'] = encryption.encrypt_password(du_metadata['du_password'])
    du_metadata['du_tenant'] = user_io.read_kbd("--> Region Tenant", [], du_tenant, True, True)
    if du_metadata['du_tenant'] == 'q':
        return ''
    du_metadata['git_branch'] = user_io.read_kbd("--> GIT Branch (for PF9-Express)", [], git_branch, True, True)
    if du_metadata['git_branch'] == 'q':
        return ''

    # Region-level parameters (overridden by host profiles)
    sys.stdout.write("\nRegion-level Host Attributes\n")
    sys.stdout.write("----------------------------\n")
    sys.stdout.write("These settings apply to all hosts within the region. For host-specific overrides, use Host Profiles.\n\n")
    du_metadata['region_auth_type'] = user_io.read_kbd("--> Authentication Type ['simple', 'sshkey']",
                                                       ['simple', 'sshkey'],
                                                       region_auth_type,
                                                       True, True)
    if du_metadata['region_auth_type'] == 'q':
        return ''
    du_metadata['auth_username'] = user_io.read_kbd("--> Username for Remote Host Access",
                                                    [],
                                                    auth_username,
                                                    True, True)
    if du_metadata['auth_username'] == 'q':
        return ''
    if du_metadata['region_auth_type'] == "simple":
        du_metadata['auth_password'] = user_io.read_kbd("--> Password for Remote Host Access",
                                                        [],
                                                        auth_password,
                                                        False, True)
        if du_metadata['auth_password'] == 'q':
            return ''
        else:
            du_metadata['auth_password'] = encryption.encrypt_password(du_metadata['auth_password'])
    else:
        du_metadata['auth_password'] = ""
  
    if du_metadata['region_auth_type'] == "sshkey":
        du_metadata['auth_ssh_key'] = user_io.read_kbd("--> SSH Key for Remote Host Access",
                                                       [],
                                                       auth_ssh_key,
                                                       True, True)
        if du_metadata['auth_ssh_key'] == 'q':
            return ''
    else:
        du_metadata['auth_ssh_key'] = ""

    # get du-specific parameters
    if selected_du_type in ['KVM','KVM/Kubernetes']:
        du_metadata['region_proxy'] = user_io.read_kbd("--> Proxy",
                                                       [],
                                                       region_proxy,
                                                       True, True)
        if du_metadata['region_proxy'] == 'q':
            return ''
        du_metadata['region_dns'] = user_io.read_kbd("--> DNS Server (comma-delimited list or IPs)",
                                                     [],
                                                     region_dns,
                                                     True, True)
        if du_metadata['region_dns'] == 'q':
            return ''
        du_metadata['region_bond_if_name'] = user_io.read_kbd("--> Interface Name (for OVS Bond)",
                                                              [],
                                                              region_bond_if_name,
                                                              True, True)
        if du_metadata['region_bond_if_name'] == 'q':
            return ''
        du_metadata['region_bond_mode'] = user_io.read_kbd("--> Bond Mode",
                                                           [],
                                                           region_bond_mode,
                                                           True, True)
        if du_metadata['region_bond_mode'] == 'q':
            return ''
        du_metadata['region_bond_mtu'] = user_io.read_kbd("--> MTU for Bond Interface",
                                                          [],
                                                          region_bond_mtu,
                                                          True, True)
        if du_metadata['region_bond_mtu'] == 'q':
            return ''
    else:
        du_metadata['region_proxy'] = ""
        du_metadata['region_dns'] = ""
        du_metadata['region_bond_if_name'] = ""
        du_metadata['region_bond_mode'] = ""
        du_metadata['region_bond_mtu'] = ""

    return(du_metadata)


def add_edit_host_profile():
    if not os.path.isfile(globals.HOST_PROFILE_FILE):
        return("define-new-host-profile")
    else:
        current_profile = datamodel.get_host_profiles()
        if len(current_profile) == 0:
            return(None)
        else:
            cnt = 1
            allowed_values = ['q','n']
            sys.stdout.write("\n")
            for profile in current_profile:
                sys.stdout.write("{}. {}\n".format(cnt,profile['host_profile_name']))
                allowed_values.append(str(cnt))
                cnt += 1
            sys.stdout.write("\n")
            user_input = user_io.read_kbd("Select Host Profile to Update (enter 'n' to create a New Profile)",
                                          allowed_values,
                                          '',
                                          True, True)
            if user_input == "q":
                return(None)
            elif user_input == "n":
                return("define-new-host-profile")
            else:
                idx = int(user_input) - 1
                return(current_profile[idx]['host_profile_name'])
        return(None)


def add_edit_bond_profile():
    if not os.path.isfile(globals.BOND_PROFILE_FILE):
        return("define-new-bond-profile")
    else:
        current_bond = datamodel.get_bond_profiles()
        if len(current_bond) == 0:
            return(None)
        else:
            cnt = 1
            allowed_values = ['q','n']
            sys.stdout.write("\n")
            for bond in current_bond:
                sys.stdout.write("{}. {}\n".format(cnt,bond['bond_name']))
                allowed_values.append(str(cnt))
                cnt += 1
            sys.stdout.write("\n")
            user_input = user_io.read_kbd("Select Bond Profile to Update (enter 'n' to create a New Profile)",
                                          allowed_values,
                                          '',
                                          True, True)
            if user_input == "q":
                return(None)
            elif user_input == "n":
                return("define-new-bond-profile")
            else:
                idx = int(user_input) - 1
                return(current_bond[idx]['bond_name'])
        return(None)


def add_edit_auth_profile():
    if not os.path.isfile(globals.AUTH_PROFILE_FILE):
        return("define-new-auth-profile")
    else:
        current_auth = datamodel.get_auth_profiles()
        if len(current_auth) == 0:
            return(None)
        else:
            cnt = 1
            allowed_values = ['q','n']
            sys.stdout.write("\n")
            for auth in current_auth:
                sys.stdout.write("{}. {}\n".format(cnt,auth['auth_name']))
                allowed_values.append(str(cnt))
                cnt += 1
            sys.stdout.write("\n")
            user_input = user_io.read_kbd("Select Auth Profile to Update (enter 'n' to create a New Profile)",
                                          allowed_values,
                                          '',
                                          True, True)
            if user_input == "q":
                return(None)
            elif user_input == "n":
                return("define-new-auth-profile")
            else:
                idx = int(user_input) - 1
                return(current_auth[idx]['auth_name'])
        return(None)


def add_edit_du():
    if not os.path.isfile(globals.CONFIG_FILE):
        return("define-new-du")
    else:
        current_config = datamodel.get_configs()
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
            user_input = user_io.read_kbd("Select Region to Update/Rediscover (enter 'n' to create a New Region)",
                                          allowed_values,
                                          '',
                                          True, True)
            if user_input == "q":
                return(None)
            elif user_input == "n":
                return("define-new-du")
            else:
                idx = int(user_input) - 1
                return(current_config[idx]['url'])
        return(None)


def select_du(du_type_filter=None):
    if not os.path.isdir(globals.CONFIG_DIR):
        sys.stdout.write("\nNo regions have been defined yet (run 'Discover/Add Region')\n")
    elif not os.path.isfile(globals.CONFIG_FILE):
        sys.stdout.write("\nNo regions have been defined yet (run 'Discover/Add Region')\n")
    else:
        current_config = datamodel.get_configs()
        if len(current_config) == 0:
            sys.stdout.write("\nNo regions have been defined yet (run 'Discover/Add Region')\n")
        else:
            # apply du filter
            if not du_type_filter:
                du_list = current_config
            else:
                du_list = []
                for du in current_config:
                    if du['du_type'] in du_type_filter:
                        du_list.append(du)

            cnt = 1
            allowed_values = ['q']
            sys.stdout.write("\n")
            for du in du_list:
                sys.stdout.write("{}. {}\n".format(cnt, du['url']))
                allowed_values.append(str(cnt))
                cnt += 1
            user_input = user_io.read_kbd("Select Region", allowed_values, '', True, True)
            if user_input == "q":
                return ''
            else:
                idx = int(user_input) - 1
                return(du_list[idx])
        return ''


def select_target_cluster(du_url):
    if not os.path.isfile(globals.CLUSTER_FILE):
        sys.stdout.write("\nNo clusters have been defined yet (run 'Discover/Add Clusters')\n")
    else:
        current_clusters = datamodel.get_clusters(du_url)
        if len(current_clusters) == 0:
            sys.stdout.write("\nNo clusters have been defined yet (run 'Discover/Add Clusters')\n")
        else:
            cnt = 1
            allowed_values = ['q']
            sys.stdout.write("\n")
            for cluster in current_clusters:
                sys.stdout.write("{}. {}\n".format(cnt, cluster['name']))
                allowed_values.append(str(cnt))
                cnt += 1
            user_input = user_io.read_kbd("Select Cluster", allowed_values, '', True, True)
            if user_input == "q":
                return ''
            else:
                idx = int(user_input) - 1
                return(current_clusters[idx])
        return ''


def add_cluster(du):
    sys.stdout.write("\nAdding Cluster to Region: {}\n".format(du['url']))
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)
    project_id, token = du_utils.login_du(du['url'],
                                          du['username'],
                                          du['password'],
                                          du['tenant'])
    if token == None:
        sys.stdout.write("--> failed to login to region")
    else:
        cluster_metadata = interview.get_cluster_metadata(du, project_id, token)
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
            datamodel.write_cluster(cluster)

            # create cluster (using qbert API)
            sys.stdout.write("\nCreating Cluster:\n")
            cluster_uuid = pmk_utils.create_cluster(du['url'],project_id,token,cluster)
            if cluster_uuid:
                sys.stdout.write("--> cluster created (uuid={})".format(cluster_uuid))
                discovered_clusters = pmk_utils.discover_du_clusters(du['url'], du['du_type'], project_id, token)
                for c in discovered_clusters:
                    datamodel.write_cluster(c)
            else:
                sys.stdout.write("ERROR: failed to create cluster\n")

            # create cluster (using express-cli)
            # express_utils.create_pmk_cluster(du,cluster)


def add_host(du):
    sys.stdout.write("\nAdding Host to Region: {}\n".format(du['url']))
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)
    project_id, token = du_utils.login_du(du['url'],
                                          du['username'],
                                          du['password'],
                                          du['tenant'])
    if token == None:
        sys.stdout.write("--> failed to login to region")
    else:
        host_metadata = interview.get_host_metadata(du, project_id, token)
        if host_metadata:
            host = datamodel.create_host_entry()
            host['du_url'] = du['url']
            host['du_host_type'] = host_metadata['du_host_type']
            host['ip'] = host_metadata['ip']
            host['uuid'] = host_metadata['uuid']
            host['ip_interfaces'] = host_metadata['ip_interfaces']
            host['hostname'] = host_metadata['hostname']
            host['record_source'] = host_metadata['record_source']
            host['sub_if_config'] = host_metadata['sub_if_config']
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
                user_input = user_io.read_kbd("--> Validate SSH connectivity to hosts", ['q','y','n'], 'n', True, True)
                if user_input == "y":
                    du_metadata = datamodel.get_du_metadata(du['url'])
                    if du_metadata:
                        ssh_status = ssh_utils.ssh_validate_login(du_metadata, host['ip'])
                        if ssh_status == True:
                            ssh_status = "OK"
                        else:
                            ssh_status = "Failed"
                    else:
                        ssh_status = "Unvalidated"
                else:
                    ssh_status = "Unvalidated"
            host['ssh_status'] = ssh_status

            # persist configurtion
            datamodel.write_host(host)


def add_host_profile(target_profile):
    if target_profile == None:
        sys.stdout.write("\nAdding Host Profile:\n")
    else:
        sys.stdout.write("\nUpdating Host Profile: {}\n".format(target_profile))

    # host_profile_metadata is created by create_host_profile_entry() - and initialized or populated from existing host profile record
    host_profile_metadata = interview.get_host_profile_settings(target_profile)
    if not host_profile_metadata:
        return(host_profile_metadata)
    else:
        # initialize host profile data structure
        host_profile = datamodel.create_host_profile_entry()
        host_profile['host_profile_name'] = host_profile_metadata['host_profile_name']
        host_profile['fk_auth_profile'] = host_profile_metadata['fk_auth_profile']
        host_profile['fk_bond_profile'] = host_profile_metadata['fk_bond_profile']
    
    # write auth profile
    datamodel.write_host_profile(host_profile)


def add_bond_profile(existing_bond_profile):
    if existing_bond_profile == None:
        sys.stdout.write("\nAdding a Bond Profile:\n")
    else:
        sys.stdout.write("\nUpdate Bond Profile:\n")

    # bond_metadata is created by create_bond_profile_entry() - and initialized or populated from existing bond record
    bond_metadata = interview.get_bond_settings(existing_bond_profile)
    if not bond_metadata:
        return(bond_metadata)
    else:
        # initialize bond data structure
        bond = datamodel.create_bond_profile_entry()
        bond['bond_name'] = bond_metadata['bond_name']
        bond['bond_ifname'] = bond_metadata['bond_ifname']
        bond['bond_mode'] = bond_metadata['bond_mode']
        bond['bond_mtu'] = bond_metadata['bond_mtu']
        bond['bond_members'] = bond_metadata['bond_members']
    
    # write auth profile
    datamodel.write_bond_profile(bond)


def add_auth_profile(existing_auth_profile):
    if existing_auth_profile == None:
        sys.stdout.write("\nAdding an Authorization (SSH) Profile:\n")
    else:
        sys.stdout.write("\nUpdate Authorization (SSH) Profile:\n")

    # auth_metadata is created by create_auth_profile_entry() - and initialized or populated from existing auth record
    auth_metadata = interview.get_auth_settings(existing_auth_profile)
    if not auth_metadata:
        return(auth_metadata)
    else:
        # initialize auth data structure
        auth = datamodel.create_auth_profile_entry()
        auth['auth_name'] = auth_metadata['auth_name']
        auth['auth_type'] = auth_metadata['auth_type']
        auth['auth_ssh_key'] = auth_metadata['auth_ssh_key']
        auth['auth_username'] = auth_metadata['auth_username']
        auth['auth_password'] = auth_metadata['auth_password']
    
    # write auth profile
    datamodel.write_auth_profile(auth)


def add_region(existing_du_url):
    if existing_du_url == None:
        sys.stdout.write("\nAdding a Region:\n")
    else:
        sys.stdout.write("\nUpdate Region:\n")

    # du_metadata is created by create_du_entry() - and initialized or populated from existing du record
    du_metadata = interview.get_du_creds(existing_du_url)
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
        sys.stdout.write("\nERROR: failed to login to Region\n")
        datamodel.write_config(du)
        return(None)

    if len(sub_regions) <2 and du['url'].replace('https://','') in sub_regions:
        sys.stdout.write("\nINFO: No Sub-Regions Have Been Detected\n\n")
        discover_targets.append(du)
    else:
        sys.stdout.write("\nThe Following Sub-Regions Have Been Detected:\n\n")
        cnt = 1
        for sub_region in sub_regions:
            if sub_region != du['url'].replace('https://',''):
                sys.stdout.write("{}. {}\n".format(cnt, sub_region))
                cnt += 1
        user_input = user_io.read_kbd("\nDo you want to discover these regions as well", ['q', 'y', 'n'], 'n', True, True)
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
        encryption = Encryption(globals.ENCRYPTION_KEY_FILE)
        sys.stdout.write("--> Adding region: {}\n".format(discover_target['url']))
        region_type = du_utils.get_du_type(discover_target['url'],
                                           discover_target['username'],
                                           discover_target['password'],
                                           discover_target['tenant'])
        if discover_target['url'] == du_metadata['du_url']:
            confirmed_region_type = user_io.read_kbd("    Confirm region type ['KVM', 'Kubernetes', 'KVM/Kubernetes', 'VMware']",
                                                     region_types,
                                                     du_metadata['du_type'],
                                                     True, True)
        else:
            confirmed_region_type = user_io.read_kbd("    Confirm region type ['KVM','Kubernetes','KVM/Kubernetes','VMware']", region_types, region_type, True, True)
        discover_target['du_type'] = confirmed_region_type

        datamodel.write_config(discover_target)

    # perform host discovery
    sys.stdout.write("\nPerforming Host Discovery (this can take a while...)\n")
    user_input = user_io.read_kbd("--> Validate SSH connectivity to hosts during discovery", ['q','y','n'], 'n', True, True)
    if user_input == "q":
        return(None)
    elif user_input == "y":
        flag_ssh = True
    else:
        flag_ssh = False
    for discover_target in discover_targets:
        num_hosts = 0
        sys.stdout.write("--> Discovering hosts for {} region: {}\n".format(discover_target['du_type'], discover_target['url']))
        project_id, token = du_utils.login_du(discover_target['url'],
                                              discover_target['username'],
                                              discover_target['password'],
                                              discover_target['tenant'])
        if project_id:
            discovered_hosts = resmgr_utils.discover_du_hosts(discover_target['url'],
                                                              discover_target['du_type'],
                                                              project_id,
                                                              token,
                                                              flag_ssh)
            for host in discovered_hosts:
                datamodel.write_host(host)
                num_hosts += 1
        sys.stdout.write("    # of hosts discovered: {}\n".format(num_hosts))

    # perform cluster discovery
    sys.stdout.write("\nPerforming Cluster Discovery (and provisioning for user-defined clusters)\n")
    for discover_target in discover_targets:
        num_clusters_discovered = 0
        num_clusters_created = 0
        if discover_target['du_type'] in ['Kubernetes','KVM/Kubernetes']:
            sys.stdout.write("--> Discovering clusters for {} region: {}\n".format(discover_target['du_type'],
                                                                                   discover_target['url']))
            encryption = Encryption(globals.ENCRYPTION_KEY_FILE)
            project_id, token = du_utils.login_du(discover_target['url'],
                                                  discover_target['username'],
                                                  discover_target['password'],
                                                  discover_target['tenant'])
            if project_id:
                # discover existing clusters
                discovered_clusters = pmk_utils.discover_du_clusters(discover_target['url'],
                                                                     discover_target['du_type'],
                                                                     project_id,
                                                                     token)

                # get existing/user-defined clusters for region
                defined_clusters = datamodel.get_clusters(discover_target['url'])

                # create any missing clusters
                for cluster in defined_clusters:
                    cluster_flag = datamodel.cluster_in_array(cluster['du_url'],
                                                              cluster['name'],
                                                              discovered_clusters)
                    if not datamodel.cluster_in_array(cluster['du_url'],
                                                      cluster['name'],
                                                      discovered_clusters):
                        pmk_utils.create_cluster(discover_target['url'],
                                                 project_id,
                                                 token,
                                                 cluster)
                        num_clusters_created += 1
                    num_clusters_discovered += 1

                if num_clusters_created > 0:
                    discovered_clusters = pmk_utils.discover_du_clusters(discover_target['url'],
                                                                         discover_target['du_type'],
                                                                         project_id,
                                                                         token)

                for cluster in discovered_clusters:
                    datamodel.write_cluster(cluster)
                sys.stdout.write("    # of clusters discovered/created: {}/{}\n".format(num_clusters_discovered,
                                                                                        num_clusters_created))

    # return
    return discover_targets
