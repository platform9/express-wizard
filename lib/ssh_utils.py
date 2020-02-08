import os
import sys
import globals
import datamodel

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


def validate_login(du_metadata, host_ip):
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


def search_discovery_data(discovery_stdout, key_name):
    discovery_data = ""
    for line in discovery_stdout:
        if line.startswith(key_name):
            discovery_data = line.strip().replace(" ",",")
            break
    return(discovery_data)


def discover_host(du_metadata, host):
    discover_metadata = {}
    source_script = "/tmp/ssh_discovery.sh"
    target_script = "/tmp/ssh_discovery.sh"
    ssh_args = "-o StrictHostKeyChecking=no -o ConnectTimeout=5"

    sys.stdout.write("    {}: ".format(host['hostname']))
    discover_metadata['message'] = "Initializing"
    if not globals.SSH_DISCOVERY:
        discover_metadata['message'] = "Disabled by Policy"
        return(discover_metadata)

    host_profile_metadata = datamodel.get_aggregate_host_profile(host['fk_host_profile'])
    if host_profile_metadata:
        auth_type = host_profile_metadata['auth_profile']['auth_type']
        ssh_key = host_profile_metadata['auth_profile']['auth_ssh_key']
        ssh_user = host_profile_metadata['auth_profile']['auth_username']
        flag_host_profile_mapped = True
    else:
        auth_type = du_metadata['auth_type']
        ssh_key = du_metadata['auth_ssh_key']
        ssh_user = du_metadata['auth_username']
        flag_host_profile_mapped = False

    if auth_type == "simple":
        return(discover_metadata)
    elif du_metadata['auth_type'] == "sshkey":
        sys.stdout.write("trying ")
        sys.stdout.flush()
        cnt = 0
        ip_list = []
        if host['ip'] != "":
            ip_list.append(host['ip'])
        else:
            for interface_ipaddr in host['ip_interfaces'].split(","):
                ip_list.append(interface_ipaddr)

        for interface_ipaddr in ip_list:
            if cnt == 0:
                sys.stdout.write("{}".format(interface_ipaddr))
            else:
                sys.stdout.write(", {}".format(interface_ipaddr))
            sys.stdout.flush()

            # try the region-level auth params - if that fails, try each defined auth-profiles
            cmd = "scp {} -i {} {} {}@{}:{}".format(ssh_args,ssh_key,source_script,ssh_user,interface_ipaddr,target_script)
            exit_status, stdout = run_cmd(cmd)
            if exit_status == 0:
                # save last discovery settings for discovery to host record
                discover_metadata['discovery-last-auth'] = "region-auth"
                discover_metadata['discovery-last-ip'] = interface_ipaddr
            else:
                cnt += 1
                if flag_host_profile_mapped:
                    continue

                # try region auth, then try all auth-profiles
                auth_profile_list = datamodel.get_auth_profile_names()
                if auth_profile_list:
                    for auth_profile_name in auth_profile_list:
                        auth_profile = datamodel.get_auth_profile_metadata(auth_profile_name)
                        ssh_key = auth_profile['auth_ssh_key']
                        ssh_user = auth_profile['auth_username']
                        cmd = "scp {} -i {} {} {}@{}:{}".format(ssh_args,ssh_key,source_script,ssh_user,interface_ipaddr,target_script)
                        exit_status, stdout = run_cmd(cmd)
                        if exit_status == 0:
                            # save last discovery settings for discovery to host record
                            discover_metadata['discovery-last-auth'] = auth_profile_name
                            discover_metadata['discovery-last-ip'] = interface_ipaddr
                            break

        cmd = "ssh {} -i {} {}@{} sudo bash {}".format(ssh_args,ssh_key,ssh_user,interface_ipaddr,target_script)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            sys.stdout.write(" - succeeded\n".format(interface_ipaddr))
            discover_metadata['primary-ip'] = search_discovery_data(stdout,"primary-ip")
            discover_metadata['interface-list'] = search_discovery_data(stdout,"interface-list")
            discover_metadata['message'] = "Complete"
        else:
            sys.stdout.write(" - failed on all interfaces\n".format(interface_ipaddr))
            discover_metadata['message'] = "Failed"
        sys.stdout.flush()
        cnt += 1
    else:
        discover_metadata['message'] = "Failed"
            
    # catch the case where SCP fails on all interfaces
    if discover_metadata['message'] == "Initializing":
        sys.stdout.write(" - failed on all interfaces\n")
        discover_metadata['message'] = "Failed"

    return(discover_metadata)

