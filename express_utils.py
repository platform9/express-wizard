import os
import sys
import user_io
import ssh_utils
import subprocess

def build_express_config(du,CONFIG_DIR):
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


def build_express_inventory(du,host_entries,CONFIG_DIR):
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
                    cluster_uuid = datamodel.get_cluster_uuid(du['url'],host['cluster_name'],CLUSTER_FILE)
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
                    cluster_uuid = datamodel.get_cluster_uuid(du['url'],host['cluster_name'],CLUSTER_FILE)
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


def checkout_branch(git_branch,EXPRESS_INSTALL_DIR):
    cmd = "cd {} && git checkout {}".format(EXPRESS_INSTALL_DIR, git_branch)
    exit_status, stdout = ssh_utils.run_cmd(cmd)

    current_branch = get_express_branch(git_branch,EXPRESS_INSTALL_DIR)
    if current_branch != git_branch:
        return(False)

    return(True)


def get_express_branch(git_branch,EXPRESS_INSTALL_DIR):
    if not os.path.isdir(EXPRESS_INSTALL_DIR):
        return(None)

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(EXPRESS_INSTALL_DIR)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        return(None)

    return(stdout[0].strip())
    

def install_express(du,EXPRESS_INSTALL_DIR,EXPRESS_REPO):
    sys.stdout.write("\nInstalling PF9-Express (branch = {})\n".format(du['git_branch']))
    if not os.path.isdir(EXPRESS_INSTALL_DIR):
        cmd = "git clone {} {}".format(EXPRESS_REPO, EXPRESS_INSTALL_DIR)
        sys.stdout.write("--> cloning repository ({})\n".format(cmd))
        exit_status, stdout = ssh_utils.run_cmd(cmd)
        if not os.path.isdir(EXPRESS_INSTALL_DIR):
            sys.stdout.write("ERROR: failed to clone PF9-Express Repository\n")
            return(False)

    sys.stdout.write("--> refreshing repository (git fetch -a)\n")
    cmd = "cd {}; git fetch -a".format(EXPRESS_INSTALL_DIR)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        sys.stdout.write("ERROR: failed to fetch branches (git fetch -)\n")
        return(False)

    current_branch = get_express_branch(du['git_branch'],EXPRESS_INSTALL_DIR)
    sys.stdout.write("--> current branch: {}\n".format(current_branch))
    if current_branch != du['git_branch']:
        sys.stdout.write("--> switching branches: {}\n".format(du['git_branch']))
        if (checkout_branch(du['git_branch'],EXPRESS_INSTALL_DIR)) == False:
            sys.stdout.write("ERROR: failed to checkout git branch: {}\n".format(du['git_branch']))
            return(False)

    cmd = "cd {}; git pull origin {}".format(EXPRESS_INSTALL_DIR,du['git_branch'])
    sys.stdout.write("--> pulling latest code (git pull origin {})\n".format(du['git_branch']))
    exit_status, stdout = ssh_utils.run_cmd(cmd)
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


def invoke_express(PF9_EXPRESS, express_config, express_inventory, target_inventory, role_flag):
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


def run_express(du,host_entries,EXPRESS_INSTALL_DIR,EXPRESS_REPO,CONFIG_DIR,PF9_EXPRESS):
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

    flag_installed = install_express(du,EXPRESS_INSTALL_DIR,EXPRESS_REPO)
    if flag_installed == True:
        express_config = build_express_config(du,CONFIG_DIR)
        if express_config:
            express_inventory = build_express_inventory(du,host_entries,CONFIG_DIR)
            if express_inventory:
                invoke_express(PF9_EXPRESS, express_config, express_inventory, target_inventory, role_flag)
    

