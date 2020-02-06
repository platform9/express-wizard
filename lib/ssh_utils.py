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
            discovery_data = line
            break
    return(discovery_data)


def discover_host(du_metadata, host):
    discover_metadata = {}
    source_script = "/tmp/ssh_discovery.sh"
    target_script = "/tmp/ssh_discovery.sh"
    ssh_args = "-o StrictHostKeyChecking=no"

    if not globals.SSH_DISCOVERY:
        discover_metadata['message'] = "discovery-disabled"
        return(discover_metadata)

    auth_profile_metadata = datamodel.get_auth_profile_metadata(host['fk_auth_profile'])
    if auth_profile_metadata:
        ssh_key = auth_profile_metadata['auth_ssh_key']
        ssh_user = auth_profile_metadata['auth_username']
    else:
        ssh_key = du_metadata['auth_ssh_key']
        ssh_user = du_metadata['auth_username']

    if du_metadata['auth_type'] == "simple":
        return(discover_metadata)
    elif du_metadata['auth_type'] == "sshkey":
        cmd = "scp {} -i {} {} {}@{}:{}".format(ssh_args,ssh_key,source_script,ssh_user,host['ip'],target_script)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            cmd = "ssh {} -i {} {}@{} sudo bash {}".format(ssh_args,ssh_key,ssh_user,host['ip'],target_script)
            exit_status, stdout = run_cmd(cmd)
            if exit_status == 0:
                discover_metadata['primary-ip'] = search_discovery_data(stdout,"primary-ip")
                discover_metadata['message'] = "discovery-complete"
            else:
                discover_metadata['message'] = "ssh-failed"
        else:
            discover_metadata['message'] = "scp-failed"
            
    return(discover_metadata)

