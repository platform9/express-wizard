import os
import sys
import shutil
import time
import user_io
import ssh_utils
import subprocess
import datamodel
import reports
import interview
import globals
from encrypt import Encryption
from help_messages import Help

def build_express_config(du):
    """write config file"""
    express_config = "{}/{}.conf".format(globals.CONFIG_DIR, "{}".format(du['url'].replace('https://','')))
    sys.stdout.write("--> Building configuration file: {}\n".format(express_config))
    encryption = Encryption(globals.ENCRYPTION_KEY_FILE)

    try:
        express_config_fh = open(express_config, "w")
        express_config_fh.write("manage_hostname|false\n")
        express_config_fh.write("manage_resolver|false\n")
        express_config_fh.write("dns_resolver1|8.8.8.8\n")
        express_config_fh.write("dns_resolver2|8.8.4.4\n")
        express_config_fh.write("os_tenant|{}\n".format(du['tenant']))
        express_config_fh.write("du_url|{}\n".format(du['url']))
        express_config_fh.write("os_username|{}\n".format(du['username']))
        express_config_fh.write("os_password|{}\n".format(encryption.decrypt_password(du['password'])))
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


def build_express_inventory(du,host_entries):
    """write inventory file"""
    express_inventory = "{}/{}.inv".format(globals.CONFIG_DIR, "{}".format(du['url'].replace('https://','')))
    sys.stdout.write("--> Building inventory file: {}\n".format(express_inventory))

    try:
        express_inventory_fh = open(express_inventory, "w")
        express_inventory_fh.write("#### Built by pf9-wizard\n")
        express_inventory_fh.write("# Global Variables (applies to ALL hosts)\n")
        express_inventory_fh.write("[all]\n")
        express_inventory_fh.write("[all:vars]\n")
        express_inventory_fh.write("ansible_user={}\n".format(du['auth_username']))
        if du['auth_type'] == "simple":
            express_inventory_fh.write("ansible_sudo_pass={}\n".format(encryption.decrypt_password(du['auth_password'])))
            express_inventory_fh.write("ansible_ssh_pass={}\n".format(encryption.decrypt_password(du['auth_password'])))
        if du['auth_type'] == "sshkey":
            express_inventory_fh.write("ansible_ssh_private_key_file={}\n".format(du['auth_ssh_key']))
        express_inventory_fh.write("custom_py_interpreter={}\n".format(globals.WIZARD_PYTHON))
        express_inventory_fh.write("ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n".format(globals.WIZARD_PYTHON))

        express_inventory_fh.write("\n# Global Network Config (applies to ALL hosts unless over-ridden by using Host Profiles)\n")
        express_inventory_fh.write("manage_network=True\n")
        express_inventory_fh.write("bond_ifname={}\n".format(du['bond_ifname']))
        express_inventory_fh.write("bond_mode={}\n".format(du['bond_mode']))
        express_inventory_fh.write("bond_mtu={}\n".format(du['bond_mtu']))

        # manage bond stanza
        express_inventory_fh.write("\n# Network Bond Configuration\n")
        express_inventory_fh.write("[bond_config]\n")
        for host in host_entries:
            if host['sub_if_config'] != "":
                express_inventory_fh.write("{} bond_sub_interfaces='{}'\n".format(host['hostname'], host['sub_if_config']))

        # manage openstack groups
        express_inventory_fh.write("\n# PMO Inventory Groups & Hosts\n")
        express_inventory_fh.write("[pmo:children]\n")
        express_inventory_fh.write("hypervisors\n")
        express_inventory_fh.write("glance\n")
        express_inventory_fh.write("cinder\n")

        # manage hypervisors group
        express_inventory_fh.write("\n# PMO Hosts\n")
        express_inventory_fh.write("[hypervisors]\n")
        cnt = 0
        for host in host_entries:
            # skip hosts without primary-ip
            if host['ip'] == "":
                continue

            # if fk_host_profile is set, add hast-level ssh attributes
            auth_override = ""
            if host['fk_host_profile'] != "":
                host_profile_metadata = datamodel.get_aggregate_host_profile(host['fk_host_profile'])
                if host_profile_metadata:
                    auth_override = "ansible_ssh_private_key_file={} ansible_ssh_user={}".format(host_profile_metadata['auth_profile']['auth_ssh_key'],host_profile_metadata['auth_profile']['auth_username'])
            else:
                if host['discovery_last_auth'] != "" and host['discovery_last_ip'] != "":
                    last_key = host['discovery_last_auth'].split(',')[0]
                    last_user = host['discovery_last_auth'].split(',')[1]
                    auth_override = "ansible_ssh_private_key_file={} ansible_ssh_user={}".format(last_key,last_user)

            if host['nova'] == "y":
                if cnt < 2:
                    express_inventory_fh.write("{} ansible_host={} {} vm_console_ip={} ha_cluster_ip={} tunnel_ip={} dhcp=on snat=on\n".format(host['hostname'],host['ip'],auth_override,host['ip'],host['ip'],host['ip']))
                else:
                    express_inventory_fh.write("{} ansible_host={} {} vm_console_ip={} ha_cluster_ip={} tunnel_ip={}\n".format(host['hostname'],host['ip'],auth_override,host['ip'],host['ip'],host['ip']))
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
        express_inventory_fh.write("\n# PMK Inventory Groups & Hosts\n")
        express_inventory_fh.write("[pmk:children]\n")
        express_inventory_fh.write("k8s_master\n")
        express_inventory_fh.write("k8s_worker\n")

        # manage K8s_master stanza
        express_inventory_fh.write("[k8s_master]\n")
        for host in host_entries:
            if host['pf9-kube'] == "y" and host['node_type'] == "master":
                # skip hosts that are already attached to a cluster
                if host['cluster_attach_status'] == "ok":
                    continue

                auth_override = ""
                if host['fk_host_profile'] != "":
                    host_profile_metadata = datamodel.get_aggregate_host_profile(host['fk_host_profile'])
                    if host_profile_metadata:
                        auth_override = "ansible_ssh_private_key_file={} ansible_ssh_user={}".format(host_profile_metadata['auth_profile']['auth_ssh_key'],host_profile_metadata['auth_profile']['auth_username'])
                else:
                    if host['discovery_last_auth'] != "" and host['discovery_last_ip'] != "":
                        last_key = host['discovery_last_auth'].split(',')[0]
                        last_user = host['discovery_last_auth'].split(',')[1]
                        auth_override = "ansible_ssh_private_key_file={} ansible_ssh_user={}".format(last_key,last_user)

                express_inventory_fh.write("{} ansible_host={} {}\n".format(host['hostname'],host['ip'],auth_override))

        # manage K8s_worker stanza
        express_inventory_fh.write("[k8s_worker]\n")
        for host in host_entries:
            if host['pf9-kube'] == "y" and host['node_type'] == "worker":
                # skip hosts that are already attached to a cluster
                if host['cluster_attach_status'] == "ok":
                    continue

                auth_override = ""
                if host['fk_host_profile'] != "":
                    host_profile_metadata = datamodel.get_aggregate_host_profile(host['fk_host_profile'])
                    if host_profile_metadata:
                        auth_override = "ansible_ssh_private_key_file={} ansible_ssh_user={}".format(host_profile_metadata['auth_profile']['auth_ssh_key'],host_profile_metadata['auth_profile']['auth_username'])
                else:
                    if host['discovery_last_auth'] != "" and host['discovery_last_ip'] != "":
                        last_key = host['discovery_last_auth'].split(',')[0]
                        last_user = host['discovery_last_auth'].split(',')[1]
                        auth_override = "ansible_ssh_private_key_file={} ansible_ssh_user={}".format(last_key,last_user)

                express_inventory_fh.write("{} ansible_host={} {}\n".format(host['hostname'],host['ip'],auth_override))
  
        # close inventory file
        express_inventory_fh.close()
    except Exception as ex:
        sys.stdout.write("ERROR: failed to write express inventory file: {}\n".format(ex.message))
        return(None)

    # validate inventory was written
    if not os.path.isfile(express_inventory):
        return(None)

    return(express_inventory)


def checkout_branch(git_branch):
    cmd = "cd {} && git checkout {}".format(globals.EXPRESS_INSTALL_DIR, git_branch)
    exit_status, stdout = ssh_utils.run_cmd(cmd)

    current_branch = get_express_branch(git_branch)
    if current_branch != git_branch:
        return(False)

    return(True)


def get_express_branch(git_branch):
    if not os.path.isdir(globals.EXPRESS_INSTALL_DIR):
        return(None)

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(globals.EXPRESS_INSTALL_DIR)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
    if exit_status != 0:
        return(None)

    return(stdout[0].strip())
    

def install_express(du):
    sys.stdout.write("\nInstalling PF9-Express (branch = {})\n".format(du['git_branch']))
    if not os.path.isdir(globals.EXPRESS_INSTALL_DIR):
        cmd = "git clone {} {}".format(globals.EXPRESS_REPO, globals.EXPRESS_INSTALL_DIR)
        sys.stdout.write("--> cloning repository ({})\n".format(cmd))
        exit_status, stdout = ssh_utils.run_cmd(cmd)
        if not os.path.isdir(globals.EXPRESS_INSTALL_DIR):
            sys.stdout.write("ERROR: failed to clone PF9-Express Repository\n")
            return(False)

    sys.stdout.write("--> refreshing repository (git fetch -a)\n")
    cmd = "cd {}; git fetch -a".format(globals.EXPRESS_INSTALL_DIR)
    exit_status, stdout = ssh_utils.run_cmd(cmd)
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

    cmd = "cd {}; git pull origin {}".format(globals.EXPRESS_INSTALL_DIR,du['git_branch'])
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
        if not current_line:
            current_line = p.stderr.readline()
        if sys.version_info[0] == 2:
            sys.stdout.write(current_line)
        else:
            sys.stdout.write(current_line.decode())
        if p.poll() != None:
            if current_line == last_line:
                sys.stdout.write("-------------------------------- Process Complete -------------------------------\n")
                break
        last_line = current_line


def create_pmk_cluster(du, cluster):
    sys.stdout.write("\nCreating Cluster (using express-cli)\n")
    express_cmd = "cluster create"
    express_cmd += " --masterVip {}".format(cluster['master_vip_ipv4'])
    express_cmd += " --masterVipIf {}".format(cluster['master_vip_iface'])
    express_cmd += " --metallbIpRange {}".format(cluster['metallb_cidr'])
    express_cmd += " --containersCidr {}".format(cluster['containers_cidr'])
    express_cmd += " --servicesCidr {}".format(cluster['services_cidr'])
    express_cmd += " --privileged {}".format(cluster['privileged'])
    express_cmd += " --appCatalogEnabled {}".format(cluster['app_catalog_enabled'])
    express_cmd += " --allowWorkloadsOnMaster {}".format(cluster['allow_workloads_on_master'])
    express_cmd += " --networkPlugin flannel"

    flag_installed = install_express(du)
    if flag_installed == True:
        express_config = build_express_config(du)
        if express_config:
            try:
                shutil.copyfile(express_config, globals.EXPRESS_CLI_CONFIG_DIR)
            except:
                sys.stdout.write("ERROR: failed to update {}\n".format(globals.EXPRESS_CLI_CONFIG_DIR))
                return()

            # build command args
            command_args = [globals.EXPRESS_CLI]
            for c in express_cmd.split(' '):
                command_args.append(c)
            command_args.append(cluster['name'])

            cmd = ""
            for c in command_args:
                cmd += "{} ".format(c)
            sys.stdout.write("Running: {}\n".format(cmd))
            c = subprocess.Popen(command_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
            tail_log(c)


def invoke_express(express_config,express_inventory,target_inventory,role_flag,silent_flag=False):
    # intialize help
    help = Help()

    sys.stdout.write("\nRunning PF9-Express\n")
    if silent_flag:
        user_input = "s"
    else:
        user_input = user_io.read_kbd("--> Installing PF9-Express Prerequisites, do you want to tail the log (enter 's' to skip)", ['q','y','n','s'], 's', True, True, help.onboard_interview("express-prereqs"))
    if user_input == 'q':
        return()
    if user_input in ['y','n']:
        p = subprocess.Popen([globals.PF9_EXPRESS,'-i','-c',express_config],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if user_input == 'y':
            sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
            tail_log(p)
        else:
            wait_for_job(p)

    if silent_flag:
        user_input = "y"
    else:
        user_input = user_io.read_kbd("--> Running PF9-Express, do you want to tail the log", ['q','y','n'], 'n', True, True, help.onboard_interview("run-express"))
    if user_input == 'q':
        return()
    if role_flag == 1:
        # install pf9-hostagent / assign roles
        if target_inventory in ['k8s_master','ks8_worker']:
            # pmk
            sys.stdout.write("Running: {} -a -b -c {} -v {} {}\n".format(globals.PF9_EXPRESS,express_config,express_inventory,target_inventory))
            cmd_args = [globals.PF9_EXPRESS,'-a','-b','-c',express_config,'-v',express_inventory,target_inventory]
            p = subprocess.Popen(cmd_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        else:
            # pmo
            sys.stdout.write("Running: {} -a -b -c {} -v {} {}\n".format(globals.PF9_EXPRESS,express_config,express_inventory,target_inventory))
            cmd_args = [globals.PF9_EXPRESS,'-a','-b','-c',express_config,'-v',express_inventory,target_inventory]
            p = subprocess.Popen(cmd_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    else:
        # install pf9-hostagent / skip role assignment
        if target_inventory in ['k8s_master','ks8_worker']:
            # pmk
            sys.stdout.write("Running: {} -b --pmk -c {} -v {} {}\n".format(globals.PF9_EXPRESS,express_config,express_inventory,target_inventory))
            cmd_args = [globals.PF9_EXPRESS,'-b','--pmk','-c',express_config,'-v',express_inventory,target_inventory]
            p = subprocess.Popen(cmd_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        else:
            # pmo
            sys.stdout.write("Running: . {} && {} -b -c {} -v {} {}\n".format(globals.WIZARD_VENV,globals.PF9_EXPRESS,express_config,express_inventory,target_inventory))
            cmd_args = ['.',globals.WIZARD_VENV,'&&',globals.PF9_EXPRESS,'-b','-c',express_config,'-v',express_inventory,target_inventory]
            p = subprocess.Popen(cmd_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    if user_input == 'y':
        sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
        tail_log(p)
    else:
        wait_for_job(p)


def invoke_express_cli(nodes, cluster_name, node_type):
    # intialize help
    help = Help()

    sys.stdout.write("\nRunning PF9-Express CLI\n")
    user_input = user_io.read_kbd("--> Do you want to tail the log", ['q','y','n'], 'y', True, True, help.onboard_interview("run-express-cli"), True)
    sys.stdout.flush()
    sys.stdout.write("\n\n>>>> DBG: just flushed stdout after reading from keyboard with timeout\n\n")
    if user_input == 'q':
        return()

    # build command args
    command_args = [globals.EXPRESS_CLI,'cluster','attach-node']
    for node in nodes:
        if node_type == "master":
            command_args.append("-m")
        else:
            command_args.append("-w")
        command_args.append(node['ip'])
    command_args.append(cluster_name)
    cmd = ""
    for c in command_args:
        cmd = "{} {}".format(cmd,c)
    sys.stdout.write("Running: {}\n".format(cmd))
    c = subprocess.Popen(command_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    if user_input == 'y':
        sys.stdout.write("----------------------------------- Start Log -----------------------------------\n")
        tail_log(c)
    else:
        wait_for_job(c)


def run_express_cli(du, onboard_params=None):
    # intialize help
    help = Help()

    # automated onboarding
    if onboard_params:
        sys.stdout.write("\nrun_express_cli() : performing automated onboarding\n")
        sys.stdout.write("--> onboard_params = \n{}\n\n".format(onboard_params))

        # validate import json
        required_keys = ['region-name']
        for rkey in required_keys:
            if not rkey in onboard_params:
                sys.stdout.write("ERROR: missing metadata in import json, missing key = {}".format(rkey))
                return()

        # determine type of onboarding (PMO -v- PMK)
        if 'cluster-name' in onboard_params:
            onboarding_type = "PMK"
        else:
            onboarding_type = "PMO"

        # perform automated onboarding - PMO
        if onboarding_type == "PMO":
            if not 'pmo-inventory' in onboard_params:
                sys.stdout.write("ERROR: missing metadata in import json, missing key = {}".format('pmo-inventory'))
                return()

            host_entries = datamodel.get_hosts(du['url'])
            if not host_entries:
                sys.stdout.write("\nINFO: there are no KVM hosts to onboard\n")
            else:
                flag_installed = install_express(du)
                if flag_installed == True:
                    express_config = build_express_config(du)
                    if express_config:
                        express_inventory = build_express_inventory(du,host_entries)
                        if express_inventory:
                            invoke_express(express_config, express_inventory, onboard_params['pmo-inventory'], 1, silent_flag=True)

        # perform automated onboarding - PMK
        if onboarding_type == "PMK":
            selected_cluster = datamodel.get_cluster_record(onboard_params['region-name'],onboard_params['cluster-name'])
            if selected_cluster:
                if 'masters' in onboard_params and onboard_params['masters'] in ['ALL','all','All']:
                    master_entries = datamodel.get_unattached_masters(selected_cluster)
                    if not master_entries:
                        sys.stdout.write("\nINFO: there are no unattached masters to attach to this cluster\n")
                    else:
                        reports.report_host_info(master_entries)
                        flag_installed = install_express(du)
                        if flag_installed == True:
                            express_config = build_express_config(du)
                            if express_config:
                                express_inventory = build_express_inventory(du,master_entries)
                                if express_inventory:
                                    try:
                                        shutil.copyfile(express_config, globals.EXPRESS_CLI_CONFIG_DIR)
                                    except:
                                        sys.stdout.write("ERROR: failed to update {}\n".format(globals.EXPRESS_CLI_CONFIG_DIR))
                                        return()

                                    sys.stdout.write("\n***INFO: invoking pf9-express for node prep (system/pip packages)\n")
                                    invoke_express(express_config,express_inventory,"k8s_master",1,silent_flag=True)
                                    sys.stdout.write("\n***INFO: invoking express-cli for node attach (cluster attach-node <cluster>))\n")
                                    invoke_express_cli(master_entries,selected_cluster['name'],"master")

                if 'workers' in onboard_params and onboard_params['workers'] in ['ALL','all','All']:
                    worker_entries = datamodel.get_unattached_workers(selected_cluster)
                    if not worker_entries:
                        sys.stdout.write("\nINFO: there are no unattached workers to attach to this cluster\n")
                    else:
                        reports.report_host_info(worker_entries)
                        flag_installed = install_express(du)
                        if flag_installed == True:
                            express_config = build_express_config(du)
                            if express_config:
                                express_inventory = build_express_inventory(du,worker_entries)
                                if express_inventory:
                                    try:
                                        shutil.copyfile(express_config, globals.EXPRESS_CLI_CONFIG_DIR)
                                    except:
                                        sys.stdout.write("ERROR: failed to update {}\n".format(globals.EXPRESS_CLI_CONFIG_DIR))
                                        return()

                                    sys.stdout.write("\n***INFO: invoking pf9-express for node prep (system/pip packages)\n")
                                    invoke_express(express_config,express_inventory,"k8s_worker",1,silent_flag=True)
                                    sys.stdout.write("\n***INFO: invoking express-cli for node attach (cluster attach-node <cluster>))\n")
                                    invoke_express_cli(worker_entries,selected_cluster['name'],"worker")
        return()

    # interview-based onboarding
    selected_cluster = interview.select_target_cluster(du['url'])
    if selected_cluster:
        user_input = user_io.read_kbd("\nAttach Master Nodes:", ['y','n','q'], 'y', True, True, help.onboard_interview("attach-masters"))
        if user_input == "y":
            master_entries = datamodel.get_unattached_masters(selected_cluster)
            if not master_entries:
                sys.stdout.write("INFO: no master nodes are mapped to this cluster\n")
            else:
                reports.report_host_info(master_entries)
                allowed_values = ['q','all']
                for node in master_entries:
                    allowed_values.append(node['hostname'])
                user_input = user_io.read_kbd("\nSelect Master Node to Attach ('all' to attach all master nodes):", allowed_values, 'all', True, True, help.onboard_interview("select-masters"))
                if user_input == "all":
                    targets = master_entries
                else:
                    idx = int(user_input) - 1
                    targets = master_entries[idx]

                flag_installed = install_express(du)
                if flag_installed == True:
                    express_config = build_express_config(du)
                    if express_config:
                        express_inventory = build_express_inventory(du,master_entries)
                        if express_inventory:
                            try:
                                shutil.copyfile(express_config, globals.EXPRESS_CLI_CONFIG_DIR)
                            except:
                                sys.stdout.write("ERROR: failed to update {}\n".format(globals.EXPRESS_CLI_CONFIG_DIR))
                                return()
                            sys.stdout.write("\n***INFO: invoking pf9-express for node prep (system/pip packages)\n")
                            invoke_express(express_config,express_inventory,"k8s_master",1)
                            sys.stdout.write("\n***INFO: invoking express-cli for node attach (cluster attach-node <cluster>))\n")
                            invoke_express_cli(targets,selected_cluster['name'],"master")

        user_input = user_io.read_kbd("\nAttach Worker Nodes:", ['y','n','q'], 'y', True, True, help.onboard_interview("attach-workers"))
        if user_input == "y":
            worker_entries = datamodel.get_unattached_workers(selected_cluster)
            if not worker_entries:
                sys.stdout.write("INFO: no worker nodes are mapped to this cluster\n")
            else:
                reports.report_host_info(worker_entries)
                allowed_values = ['q','all']
                for node in worker_entries:
                    allowed_values.append(node['hostname'])
                user_input = user_io.read_kbd("\nSelect Worker Node to Attach ('all' to attach all worker nodes):", allowed_values, 'all', True, True, help.onboard_interview("select-workers"))
                if user_input == "all":
                    targets = worker_entries
                else:
                    idx = int(user_input) - 1
                    targets = worker_entries[idx]

                flag_installed = install_express(du)
                if flag_installed == True:
                    express_config = build_express_config(du)
                    if express_config:
                        express_inventory = build_express_inventory(du,worker_entries)
                        if express_inventory:
                            try:
                                shutil.copyfile(express_config, globals.EXPRESS_CLI_CONFIG_DIR)
                            except:
                                sys.stdout.write("ERROR: failed to update {}\n".format(globals.EXPRESS_CLI_CONFIG_DIR))
                                return()
                            sys.stdout.write("\n***INFO: invoking pf9-express for node prep (system/pip packages)\n")
                            invoke_express(express_config,express_inventory,"k8s_worker",1)
                            sys.stdout.write("\n***INFO: invoking express-cli for node attach (cluster attach-node <cluster>))\n")
                            invoke_express_cli(targets,selected_cluster['name'],"worker")


def run_express(du,host_entries):
    # intialize help
    help = Help()

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
    user_input = user_io.read_kbd("\nSelect Inventory (to run PF9-Express against)", allowed_values, '1', True, True, help.onboard_interview("select-inventory"))
    if user_input == "q":
        return()
    if int(user_input) != custom_idx:
        idx = int(user_input) - 1
        target_inventory = express_inventories[idx]
    else:
        user_input = user_io.read_kbd("\nInventory Targets (comma/space-delimitted list of hostnames)", [], '', True, True, help.onboard_interview("custom-inventory"))
        target_inventory = user_input

    sys.stdout.write("\nPF9-Express Role Assignment\n")
    sys.stdout.write("    1. Install Hostagent\n")
    sys.stdout.write("    2. Install Hostagent and Assign Roles\n")
    assign_roles = user_io.read_kbd("\nRole Assignment", ['q','1','2'], '2', True, True, help.onboard_interview("role-assignment"))
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
            express_inventory = build_express_inventory(du,host_entries)
            if express_inventory:
                invoke_express(express_config, express_inventory, target_inventory, role_flag)
    

