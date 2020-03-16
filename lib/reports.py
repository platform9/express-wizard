import os
import sys
import globals
import du_utils
import datamodel


def map_yn(map_key):
    if map_key == "y":
        return("Enabled")
    elif map_key == "n":
        return("Disabled")
    elif map_key == "":
        return("Disabled")
    else:
        return("failed-to-map")


def report_host_profiles(host_profile_entries):
    from prettytable import PrettyTable

    sys.stdout.write("\n------------ Host Templates ------------\n")
    if not os.path.isfile(globals.HOST_PROFILE_FILE):
        sys.stdout.write("No host profiles have been defined yet (run 'Manage Host Profiles')\n")
        return()

    host_profile_table = PrettyTable()
    host_profile_table.title = "Host Templates"
    host_profile_table.field_names = ["Template Name","Authorization Profile","Role Profile","Bond Profile"]
    host_profile_table.align["Template Name"] = "l"
    host_profile_table.align["Authorization Profile"] = "l"
    host_profile_table.align["Role Profile"] = "l"
    host_profile_table.align["Bond Profile"] = "l"

    for host_profile in host_profile_entries:
        host_profile_table.add_row([host_profile['host_profile_name'],host_profile['fk_auth_profile'],host_profile['fk_role_profile'],host_profile['fk_bond_profile']])

    print(host_profile_table)


def report_role_profiles(role_entries):
    from prettytable import PrettyTable

    sys.stdout.write("\n------------ Role Profiles ------------\n")
    if not os.path.isfile(globals.ROLE_PROFILE_FILE):
        sys.stdout.write("No role profiles have been defined yet (run 'Manage Role Profiles')\n")
        return()

    role_table = PrettyTable()
    role_table.title = "Role Profiles"
    role_table.field_names = ["Profile Name","Host Type","Nova","Glance","Cinder","Designate","K8s NodeType"]
    role_table.align["Profile Name"] = "l"
    role_table.align["Host Type"] = "l"
    role_table.align["Nova"] = "l"
    role_table.align["Glance"] = "l"
    role_table.align["Cinder"] = "l"
    role_table.align["Designate"] = "l"
    role_table.align["K8s NodeType"] = "l"

    for role in role_entries:
        if role['nova'] == 'y':
            node_type = "OpenStack (PMO)"
        if role['pf9-kube'] == 'y':
            node_type = "Kubernetes (PMK)"
        role_table.add_row([role['role_name'],node_type,map_yn(role['nova']),map_yn(role['glance']),map_yn(role['cinder']),map_yn(role['designate']),role['node_type']])

    print(role_table)


def report_bond_profiles(bond_entries):
    from prettytable import PrettyTable

    sys.stdout.write("\n------------ Bond Profiles ------------\n")
    if not os.path.isfile(globals.BOND_PROFILE_FILE):
        sys.stdout.write("No bond profiles have been defined yet (run 'Manage Bond Profiles')\n")
        return()

    bond_table = PrettyTable()
    bond_table.title = "Bond Profiles"
    bond_table.field_names = ["Profile Name","Bond Interface Name","Bond Mode","Bond MTU","Member Interfaces"]
    bond_table.align["Profile Name"] = "l"
    bond_table.align["Bond Interface Name"] = "l"
    bond_table.align["Bond Mode"] = "l"
    bond_table.align["Bond MTU"] = "l"
    bond_table.align["Member Interfaces"] = "l"

    for bond in bond_entries:
        bond_mode = globals.bond_modes[int(bond['bond_mode'])]
        bond_table.add_row([bond['bond_name'],bond['bond_ifname'],bond_mode,bond['bond_mtu'],bond['bond_members']])

    print(bond_table)


def report_auth_profiles(auth_entries):
    from prettytable import PrettyTable

    sys.stdout.write("\n------ Authorization Profiles (SSH Access) ------\n")
    if not os.path.isfile(globals.AUTH_PROFILE_FILE):
        sys.stdout.write("No authorization profiles have been defined yet (run 'Add/Update SSH Profiles')\n")
        return()

    auth_table = PrettyTable()
    auth_table.title = "Authorization Profiles"
    auth_table.field_names = ["Profile Name","Auth Type","Remote Username","SSH Key","SSH Password"]
    auth_table.align["Profile Name"] = "l"
    auth_table.align["Auth Type"] = "l"
    auth_table.align["Remote Username"] = "l"
    auth_table.align["SSH Key"] = "l"
    auth_table.align["SSH Password"] = "l"

    for auth in auth_entries:
        if auth['auth_password'] == "":
            auth_password = ""
        else:
            auth_password = "**********"
        auth_table.add_row([auth['auth_name'],auth['auth_type'],auth['auth_username'],auth['auth_ssh_key'],auth_password])

    print(auth_table)


def report_du_info(du_entries):
    from prettytable import PrettyTable

    sys.stdout.write("\n------ Region(s) ------\n")
    if not os.path.isfile(globals.CONFIG_FILE):
        sys.stdout.write("No regions have been defined yet (run 'Discover/Add Region')\n")
        return()

    du_table = PrettyTable()
    du_table.title = "Region Configuration"
    du_table.field_names = ["Region URL","Region Auth","Region Type","Region Name","Tenant","SSH Auth Type","SSH User","# Hosts"]
    du_table.align["Region URL"] = "l"
    du_table.align["Region Auth"] = "l"
    du_table.align["Region Type"] = "l"
    du_table.align["Region Name"] = "l"
    du_table.align["Tenant"] = "l"
    du_table.align["SSH Auth Type"] = "l"
    du_table.align["SSH User"] = "l"
    du_table.align["# Hosts"] = "l"

    for du in du_entries:
        num_hosts = "-"
        project_id, token = du_utils.login_du(du['url'], du['username'], du['password'], du['tenant'])
        if token == None:
            auth_status = "Failed"
            region_type = ""
        else:
            auth_status = "OK"
            if du['auth_type'] == "sshkey":
                ssh_keypass = du['auth_ssh_key']
            else:
                ssh_keypass = "********"
            num_hosts = datamodel.get_defined_hosts(du['url'])

        du_table.add_row([du['url'], auth_status, du['du_type'], du['region'], du['tenant'], du['auth_type'], du['auth_username'], num_hosts])

    print(du_table)


def report_cluster_info(cluster_entries):
    from prettytable import PrettyTable

    sys.stdout.write("\n------ Kubernetes Clusters ------\n")
    if not os.path.isfile(globals.CLUSTER_FILE):
        sys.stdout.write("No clusters have been defined yet (run 'Discover/Add Cluster')\n")
        return()

    du_table = PrettyTable()
    du_table.field_names = ["Name","Containers","Services","VIP","MetalLB","Taint","UUID"]
    du_table.title = "Kubernetes Clusters"
    du_table.header = True
    du_table.align["Name"] = "l"
    du_table.align["Containers"] = "l"
    du_table.align["Services"] = "l"
    du_table.align["VIP"] = "l"
    du_table.align["MetalLB"] = "l"
    du_table.align["Taint"] = "l"
    du_table.align["UUID"] = "l"

    for cluster in cluster_entries:
        print("--------------------------------------")
        table_row = [
            cluster['name'],
            cluster['containers_cidr'],
            cluster['services_cidr'],
            cluster['master_vip_ipv4'],
            cluster['metallb_cidr'],
            cluster['allow_workloads_on_master'],
            cluster['uuid']
        ]
        du_table.add_row(table_row)

    print(du_table)


def report_host_info(host_entries):
    from prettytable import PrettyTable

    if not os.path.isfile(globals.HOST_FILE):
        sys.stdout.write("\n------ Hosts ------\n")
        sys.stdout.write("No hosts have been defined yet (run 'Discover/Add Hosts')\n")
        return()

    if len(host_entries) == 0:
        sys.stdout.write("\n------ Hosts ------\n")
        sys.stdout.write("No hosts have been defined yet (run 'Discover/Add Hosts')\n")
        return()
    
    du_metadata = datamodel.get_du_metadata(host_entries[0]['du_url'])

    # display KVM hosts
    if du_metadata['du_type'] == "KVM":
        host_table = PrettyTable()
        host_table.field_names = ["Hostname","Primary IP","Host Template","Discovery Status","Source","IP Interfaces"]
        host_table.title = "KVM Hosts"
        host_table.align["Hostname"] = "l"
        host_table.align["Primary IP"] = "l"
        host_table.align["Host Template"] = "l"
        host_table.align["SSH Auth"] = "l"
        host_table.align["Source"] = "l"
        host_table.align["IP Interfaces"] = "l"
        num_kvm_rows = 0
        for host in host_entries:
            if host['du_host_type'] != "kvm":
                continue
            host_table.add_row(
                [host['hostname'],
                host['ip'],
                host['fk_host_profile'],
                host['ssh_status'],
                host['record_source'],
                host['ip_interfaces']]
            )
            num_kvm_rows += 1
        if num_kvm_rows > 0:
            sys.stdout.write("\n------ KVM Hosts ------\n")
            print(host_table)

    if du_metadata['du_type'] == "VMware":
        host_table = PrettyTable()
        host_table.field_names = ["HOSTNAME","Primary IP","Discovery Status","Source","Nova","Glance","Cinder","Designate"]
        host_table.title = "KVM Hosts"
        host_table.align["HOSTNAME"] = "l"
        host_table.align["Primary IP"] = "l"
        host_table.align["SSH Auth"] = "l"
        host_table.align["Source"] = "l"
        host_table.align["Nova"] = "l"
        host_table.align["Glance"] = "l"
        host_table.align["Cinder"] = "l"
        host_table.align["Designate"] = "l"
        num_kvm_rows = 0
        for host in host_entries:
            if host['du_host_type'] != "kvm":
                continue
            host_table.add_row([host['hostname'],host['ip'], host['ssh_status'], host['record_source'], map_yn(host['nova']), map_yn(host['glance']), map_yn(host['cinder']), map_yn(host['designate'])])
            num_kvm_rows += 1
        if num_kvm_rows > 0:
            sys.stdout.write("\n------ VMware Gateways ------\n")
            print(host_table)

    # print K8s nodes
    host_table = PrettyTable()
    host_table.field_names = ["HOSTNAME","Primary IP","Host Template","Discovery Status","Source","Node Type","Cluster Name","Attached"]
    host_table.title = "Kubernetes Hosts"
    host_table.align["HOSTNAME"] = "l"
    host_table.align["Primary IP"] = "l"
    host_table.align["Host Template"] = "l"
    host_table.align["SSH Auth"] = "l"
    host_table.align["Source"] = "l"
    host_table.align["Node Type"] = "l"
    host_table.align["Cluster Name"] = "l"
    host_table.align["Attached"] = "l"
    num_k8s_rows = 0
    for host in host_entries:
        if host['du_host_type'] != "kubernetes":
            continue
        if host['cluster_name'] == "":
            cluster_assigned = "Unassigned"
        else:
            cluster_assigned = host['cluster_name']

        host_table.add_row([host['hostname'], host['ip'], host['fk_host_profile'], host['ssh_status'], host['record_source'], host['node_type'], cluster_assigned, host['cluster_attach_status']])
        num_k8s_rows += 1
    if num_k8s_rows > 0:
        sys.stdout.write("\n------ Kubernetes Nodes ------\n")
        print(host_table)

    # print unassigned hosts
    unassigned_table = PrettyTable()
    unassigned_table.field_names = ["HOSTNAME","Primary IP","Host Template","Discovery Status","IP Interfaces"]
    unassigned_table.title = "Unassigned Hosts"
    unassigned_table.align["HOSTNAME"] = "l"
    unassigned_table.align["Primary IP"] = "l"
    unassigned_table.align["SSH Auth"] = "l"
    unassigned_table.align["Source"] = "l"
    unassigned_table.align["IP Interfaces"] = "l"
    num_unassigned_rows = 0
    for host in host_entries:
        if host['du_host_type'] != "unassigned":
            continue

        unassigned_table.add_row([host['hostname'], host['ip'], host['ssh_status'], host['record_source'],host['ip_interfaces']])
        num_unassigned_rows += 1
    if num_unassigned_rows > 0:
        sys.stdout.write("\n------ Unassigned Hosts ------\n")
        print(unassigned_table)


