import os
import sys
import time
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


def test_ip_via_ssh(ssh_key, ssh_username, host_ip):
    cmd = "ssh -o StrictHostKeyChecking=no -i {} {}@{} 'echo 201'".format(ssh_key, ssh_username, host_ip)
    exit_status, stdout = run_cmd(cmd)
    if exit_status == 0:
        return(True)
    else:
        return(False)


def wait_for_ip(du, host_ip):
    TIMEOUT = 3
    POLL_INTERVAL = 10
    timeout = int(time.time()) + (60 * TIMEOUT)
    flag_ip_responding = False
    sys.stdout.write("waiting for ip to respond using: ssh {}@{}): ".format(du['auth_username'],host_ip))
    sys.stdout.flush()

    while True:
        ip_status = test_ip_via_ssh(du['auth_ssh_key'],du['auth_username'],host_ip)
        if ip_status:
            flag_ip_responding = True
            break
        elif int(time.time()) > timeout:
            break
        else:
            time.sleep(POLL_INTERVAL)

    # enforce TIMEOUT
    if not flag_ip_responding:
        sys.stdout.write("TIMEOUT\n")
        sys.stdout.flush()
        return(False)

    sys.stdout.write("OK\n")
    sys.stdout.flush()
    return(True)


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
    source_script = "{}/../scripts/ssh_discovery.sh".format(os.path.dirname(os.path.realpath(__file__))) 
    target_script = "/tmp/ssh_discovery.sh"
    ssh_args = "-o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes"
    discover_metadata = {}
    cnt = 0

    # try last known-good auth profile (if exists)
    sys.stdout.write("    {}: ".format(host['hostname']))
    sys.stdout.write("trying ")
    sys.stdout.flush()
    discover_metadata['message'] = "Initializing"
    if host['discovery_last_auth'] != "" and host['discovery_last_ip'] != "":
        cnt += 1
        last_ip = host['discovery_last_ip']
        last_key = host['discovery_last_auth'].split(',')[0]
        last_user = host['discovery_last_auth'].split(',')[1]

        cmd = "scp {} -i {} {} {}@{}:{}".format(ssh_args,last_key,source_script,last_user,last_ip,target_script)
        sys.stdout.write("{} ".format(last_ip))
        sys.stdout.flush()
        if exit_status == 0:
            cmd = "ssh {} -i {} {}@{} sudo bash {}".format(ssh_args,last_key,last_user,last_ip,target_script)
            exit_status, stdout = run_cmd(cmd)
            if exit_status == 0:
                discover_metadata['message'] = "Complete"
                discover_metadata['primary-ip'] = search_discovery_data(stdout,"primary-ip")
                discover_metadata['interface-list'] = search_discovery_data(stdout,"interface-list")
                discover_metadata['discovery-last-auth'] = "{},{}".format(last_key,last_user)
                discover_metadata['discovery-last-ip'] = last_ip
                sys.stdout.write(" - succeeded\n")
                sys.stdout.flush()
                return(discover_metadata)

    # NOTE: if last-auth succeeds, ths code path will not be followed
    # try region auth, then all auth-profiles
    host_profile_metadata = datamodel.get_aggregate_host_profile(host['fk_host_profile'])
    if 'auth_profile' in host_profile_metadata:
        ssh_key = host_profile_metadata['auth_profile']['auth_ssh_key']
        ssh_user = host_profile_metadata['auth_profile']['auth_username']
    else:
        ssh_key = du_metadata['auth_ssh_key']
        ssh_user = du_metadata['auth_username']

    # build list of IP address to attempt discovery on (use primary IP if set)
    ip_list = []
    if host['ip'] != "":
        ip_list.append(host['ip'])
    if host['public_ip'] != "":
        ip_list.append(host['public_ip'])
    if len(ip_list) == 0:
        for interface_ipaddr in host['ip_interfaces'].split(","):
            ip_list.append(interface_ipaddr)

    flag_scp_succeeded = False
    for interface_ipaddr in ip_list:
        if cnt == 0:
            sys.stdout.write("{}".format(interface_ipaddr))
        else:
            sys.stdout.write(", {}".format(interface_ipaddr))
        sys.stdout.flush()
        cnt += 1

        # try the region-level auth params
        cmd = "scp {} -i {} {} {}@{}:{}".format(ssh_args,ssh_key,source_script,ssh_user,interface_ipaddr,target_script)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            flag_scp_succeeded = True
            break

        # try all auth-profiles
        auth_profile_list = datamodel.get_auth_profile_names()
        for auth_profile_name in auth_profile_list:
            auth_profile = datamodel.get_auth_profile_metadata(auth_profile_name)
            ssh_key = auth_profile['auth_ssh_key']
            ssh_user = auth_profile['auth_username']
            cmd = "scp {} -i {} {} {}@{}:{}".format(ssh_args,ssh_key,source_script,ssh_user,interface_ipaddr,target_script)
            exit_status, stdout = run_cmd(cmd)
            if exit_status == 0:
                flag_scp_succeeded = True
                break

    if flag_scp_succeeded:
        # update last-auth
        discover_metadata['discovery-last-auth'] = "{},{}".format(ssh_key,ssh_user)
        discover_metadata['discovery-last-ip'] = interface_ipaddr

        cmd = "ssh {} -i {} {}@{} sudo bash {}".format(ssh_args,ssh_key,ssh_user,interface_ipaddr,target_script)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            sys.stdout.write(" - succeeded\n")
            sys.stdout.flush()
            discover_metadata['primary-ip'] = search_discovery_data(stdout,"primary-ip")
            discover_metadata['interface-list'] = search_discovery_data(stdout,"interface-list")
            discover_metadata['message'] = "Complete"
        else:
            sys.stdout.write(" - failed on all interfaces\n".format(interface_ipaddr))
            sys.stdout.flush()
            discover_metadata['message'] = "Failed"

    # catch the case where SCP fails on all interfaces
    if discover_metadata['message'] == "Initializing":
        sys.stdout.write(" - failed on all interfaces\n")
        sys.stdout.flush()
        discover_metadata['message'] = "Failed"

    return(discover_metadata)

