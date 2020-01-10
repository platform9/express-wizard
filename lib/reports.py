import os
import sys
import du_utils
import datamodel


def map_yn(map_key):
    if map_key == "y":
        return("Enabled")
    elif map_key == "n":
        return("Disabled")
    else:
        return("failed-to-map")


def report_du_info(du_entries,CONFIG_FILE,HOST_FILE):
    from prettytable import PrettyTable

    sys.stdout.write("\n------ Region(s) ------\n")
    if not os.path.isfile(CONFIG_FILE):
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
        project_id, token = du_utils.login_du(du['url'],du['username'],du['password'],du['tenant'])
        if token == None:
            auth_status = "Failed"
            region_type = ""
        else:
            auth_status = "OK"
            if du['auth_type'] == "sshkey":
                ssh_keypass = du['auth_ssh_key']
            else:
                ssh_keypass = "********"
            num_hosts = datamodel.get_defined_hosts(du['url'],HOST_FILE)

        du_table.add_row([du['url'], auth_status, du['du_type'], du['region'], du['tenant'], du['auth_type'], du['auth_username'], num_hosts])

    print(du_table)


def report_cluster_info(cluster_entries,CLUSTER_FILE):
    from prettytable import PrettyTable

    sys.stdout.write("\n------ Kubernetes Clusters ------\n")
    if not os.path.isfile(CLUSTER_FILE):
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
        print(cluster)
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


def report_host_info(host_entries,HOST_FILE,CONFIG_FILE):
    from prettytable import PrettyTable

    sys.stdout.write("\n------ Hosts ------\n")
    if not os.path.isfile(HOST_FILE):
        sys.stdout.write("No hosts have been defined yet (run 'Discover/Add Hosts')\n")
        return()

    if len(host_entries) == 0:
        sys.stdout.write("No hosts have been defined yet (run 'Discover/Add Hosts')\n")
        return()
    
    du_metadata = datamodel.get_du_metadata(host_entries[0]['du_url'],CONFIG_FILE)

    # display KVM hosts
    if du_metadata['du_type'] == "KVM":
        host_table = PrettyTable()
        host_table.field_names = ["HOSTNAME","Primary IP","SSH Auth","Source","Nova","Glance","Cinder","Designate","IP Interfaces"]
        host_table.title = "KVM Hosts"
        host_table.align["HOSTNAME"] = "l"
        host_table.align["Primary IP"] = "l"
        host_table.align["SSH Auth"] = "l"
        host_table.align["Source"] = "l"
        host_table.align["Nova"] = "l"
        host_table.align["Glance"] = "l"
        host_table.align["Cinder"] = "l"
        host_table.align["Designate"] = "l"
        host_table.align["IP Interfaces"] = "l"
        num_kvm_rows = 0
        for host in host_entries:
            if host['du_host_type'] != "kvm":
                continue
            host_table.add_row([host['hostname'],host['ip'], host['ssh_status'], host['record_source'], map_yn(host['nova']), map_yn(host['glance']), map_yn(host['cinder']), map_yn(host['designate']), host['ip_interfaces']])
            num_kvm_rows += 1
        if num_kvm_rows > 0:
            sys.stdout.write("\n------ KVM Hosts ------\n")
            print(host_table)

    if du_metadata['du_type'] == "VMware":
        host_table = PrettyTable()
        host_table.field_names = ["HOSTNAME","Primary IP","SSH Auth","Source","Nova","Glance","Cinder","Designate"]
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
    host_table.field_names = ["HOSTNAME","Primary IP","SSH Auth","Source","Node Type","Cluster Name","Attached"]
    host_table.title = "Kubernetes Hosts"
    host_table.align["HOSTNAME"] = "l"
    host_table.align["Primary IP"] = "l"
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

        host_table.add_row([host['hostname'], host['ip'], host['ssh_status'], host['record_source'], host['node_type'], cluster_assigned, host['cluster_attach_status']])
        num_k8s_rows += 1
    if num_k8s_rows > 0:
        sys.stdout.write("\n------ Kubernetes Nodes ------\n")
        print(host_table)

    # print unassigned hosts
    unassigned_table = PrettyTable()
    unassigned_table.field_names = ["HOSTNAME","Primary IP","SSH Auth","Source","IP Interfaces"]
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


