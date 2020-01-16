####################################################################################################
## PF9-Wizard | Onboarding Tool for Platform9 
## Copyright(c) 2019 Platform9 Systems, Inc.
##
## (. ~/.pf9-wizard/wizard-venv/bin/activate && python wizard.py -l)
####################################################################################################
import os
import sys

####################################################################################################
# early globals/functions
def fail(m=None):
    sys.stdout.write("ASSERT: {}\n".format(m))
    sys.exit(1)

# validate python version
if not sys.version_info[0] in (2,3):
    fail("Unsupported Python Version: {}\n".format(sys.version_info[0]))

# include globals.py - handle case where it lives in /tmp (e.g. wizard.sh)
if os.path.isfile("/tmp/globals.py"):
    sys.path.append("/tmp")

####################################################################################################
# module imports
try:
    import globals,argparse,requests,urllib3,json,prettytable,signal,getpass,argparse,subprocess,time,pprint
except:
    except_str = str(sys.exc_info()[1])
    module_name = except_str.split(' ')[-1]
    fail("Failed to import python module: {}".format(module_name))

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####################################################################################################
# functions
def _parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--init", "-i", help="Initialize Configuration (delete all regions/hosts)", action="store_true")
    ap.add_argument("--local", "-l", help="Use local libraries (for development only)", action="store_true")
    ap.add_argument('--export', "-e", help="Name of region to export", required=False)
    return ap.parse_args()


def dump_var(target_var):
    from inspect import getmembers
    from pprint import pprint
    pprint(getmembers(target_var))


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


def dump_text_file(target_file):
    BAR = "======================================================================================================"
    try:
        target_fh = open(target_file,mode='r')
        sys.stdout.write('\n========== {0:^80} ==========\n'.format(target_file))
        sys.stdout.write(target_fh.read())
        sys.stdout.write('{}\n'.format(BAR))
        target_fh.close()
    except:
        sys.stdout.write("ERROR: failed to open file: {}".format(target_file))


def view_log(log_files):
    cnt = 1
    allowed_values = ['q']
    for log_file in log_files:
        sys.stdout.write("{}. {}\n".format(cnt,log_file))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("Select Log", allowed_values, '', True, True)
    if user_input != "q":
        idx = int(user_input) - 1
        target_log = log_files[idx]
        target_log_path = "{}/{}".format(globals.EXPRESS_LOG_DIR,target_log)
        dump_text_file(target_log_path)


def get_logs():
    log_files = []
    if not os.path.isdir(globals.EXPRESS_LOG_DIR):
        return(log_files)

    for r, d, f in os.walk(globals.EXPRESS_LOG_DIR):
        for file in f:
            if file == ".keep":
                continue
            log_files.append(file)

    return(log_files)


def view_inventory(du, host_entries):
    express_inventory = express_utils.build_express_inventory(du,host_entries)
    if express_inventory:
        dump_text_file(express_inventory)
    else:
        sys.stdout.write("ERROR: failed to build inventory file: {}".format(express_inventory))


def view_config(du):
    express_config = express_utils.build_express_config(du)
    if express_config:
        dump_text_file(express_config)
    else:
        sys.stdout.write("ERROR: failed to build configuration file: {}".format(express_config))


def dump_database(db_file):
    if os.path.isfile(db_file):
        exit_status, stdout = run_cmd("cat {} | jq '.'".format(db_file))
        if exit_status == 0:
            for line in stdout:
                sys.stdout.write(line)
        else:
            with open(db_file) as json_file:
                db_json = json.load(json_file)
            pprint.pprint(db_json)


def action_header(title):
    MAX_WIDTH = 132
    title = "  {}  ".format(title)
    sys.stdout.write("\n{}".format(title.center(MAX_WIDTH,'*')))


def display_menu1():
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("**           Platform9 Express Wizard            **\n")
    sys.stdout.write("**            -- Maintenance Menu --             **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Delete Region\n")
    sys.stdout.write("2. Delete Host\n")
    sys.stdout.write("3. Display Region Database\n")
    sys.stdout.write("4. Display Host Database\n")
    sys.stdout.write("5. Display Cluster Database\n")
    sys.stdout.write("6. View Configuration File\n")
    sys.stdout.write("7. View Inventory File\n")
    sys.stdout.write("8. View Logs\n")
    sys.stdout.write("***************************************************\n")


def display_menu0():
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("**           Platform9 Express Wizard            **\n")
    sys.stdout.write("**               -- Main Menu --                 **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Discover/Add Regions\n")
    sys.stdout.write("2. Discover/Add Hosts\n")
    sys.stdout.write("3. Discover/Add Clusters\n")
    sys.stdout.write("4. Show Region\n")
    sys.stdout.write("5. Onboard Host to Region\n")
    sys.stdout.write("6. Maintenance\n")
    sys.stdout.write("***************************************************\n")


def menu_level1():
    user_input = ""
    while not user_input in ['q','Q']:
        display_menu1()
        user_input = user_io.read_kbd("Enter Selection", [], '', True, True)
        if user_input == '1':
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    datamodel.delete_du(selected_du)
        elif user_input == '2':
            sys.stdout.write("\nNot Implemented\n")
        elif user_input == '3':
            dump_database(globals.CONFIG_FILE)
        elif user_input == '4':
            dump_database(globals.HOST_FILE)
        elif user_input == '5':
            dump_database(globals.CLUSTER_FILE)
        elif user_input == '6':
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    new_host = view_config(selected_du)
        elif user_input == '7':
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    host_entries = datamodel.get_hosts(selected_du['url'])
                    new_host = view_inventory(selected_du, host_entries)
        elif user_input == '8':
            log_files = get_logs()
            if len(log_files) == 0:
                sys.stdout.write("\nNo Logs Found")
            else:
                view_log(log_files)
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")
        sys.stdout.write("\n")


def menu_level0():
    user_input = ""
    sys.stdout.write("\n")
    while not user_input in ['q','Q']:
        display_menu0()
        user_input = user_io.read_kbd("Enter Selection", [], '', True, True)
        if user_input == '1':
            action_header("MANAGE REGIONS")
            selected_du = interview.add_edit_du()
            if selected_du != None:
                if selected_du == "define-new-du":
                    target_du = None
                else:
                    target_du = selected_du
                new_du_list = interview.add_region(target_du)
                if new_du_list:
                    reports.report_du_info(new_du_list)
        elif user_input == '2':
            action_header("MANAGE HOSTS")
            sys.stdout.write("\nSelect Region to add Host to:")
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    flag_more_hosts = True
                    while flag_more_hosts:
                        new_host = interview.add_host(selected_du)
                        user_input = user_io.read_kbd("\nAdd Another Host?", ['y','n'], 'y', True, True)
                        if user_input == "n":
                            flag_more_hosts = False
        elif user_input == '3':
            action_header("MANAGE CLUSTERS")
            sys.stdout.write("\nSelect Region to add Cluster to:")
            selected_du = interview.select_du(['Kubernetes','KVM/Kubernetes'])
            if selected_du:
                if selected_du != "q":
                    new_cluster = interview.add_cluster(selected_du)
        elif user_input == '4':
            action_header("SHOW REGION")
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    du_entries = datamodel.get_configs(selected_du['url'])
                    reports.report_du_info(du_entries)
                    host_entries = datamodel.get_hosts(selected_du['url'])
                    reports.report_host_info(host_entries)
                    if selected_du['du_type'] in ['Kubernetes','KVM/Kubernetes']:
                        cluster_entries = datamodel.get_clusters(selected_du['url'])
                        reports.report_cluster_info(cluster_entries)
        elif user_input == '5':
            action_header("ONBOARD HOSTS")
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    if selected_du['du_type'] == "Kubernetes":
                        sys.stdout.write("\nKubernetes Region: onboarding K8s nodes\n")
                        express_utils.run_express_cli(selected_du)
                    elif selected_du['du_type'] == "KVM":
                        sys.stdout.write("\nKVM Region: onboarding KVM hyervisors\n")
                        host_entries = datamodel.get_hosts(selected_du['url'])
                        express_utils.run_express(selected_du, host_entries)
        elif user_input == '6':
            menu_level1()
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")

        if user_input != '7':
            sys.stdout.write("\n")


def ssh_validate_login(du_metadata, host_ip):
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


def get_branch(install_dir):
    if not os.path.isdir(install_dir):
        return(None)

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(install_dir)
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        return(None)

    return(stdout[0].strip())
    

def checkout_git_branch(branch_name,install_dir):
    cmd = "cd {} && git checkout {}".format(install_dir, branch_name)
    exit_status, stdout = run_cmd(cmd)

    current_branch = get_branch(install_dir)
    if current_branch != branch_name:
        return(False)

    return(True)


## main
args = _parse_args()

# perform initialization (if invoked with '--init')
if args.init:
    sys.stdout.write("INFO: initializing configuration\n")
    if os.path.isfile(globals.HOST_FILE):
        os.remove(globals.HOST_FILE)
    if os.path.isfile(globals.CONFIG_FILE):
        os.remove(globals.CONFIG_FILE)
    if os.path.isfile(globals.CLUSTER_FILE):
        os.remove(globals.CLUSTER_FILE)

# define dependent repositories
required_repos = [
    {
        "repo_url": "https://github.com/platform9/express.git",
        "repo_name": "Express",
        "install_dir": globals.EXPRESS_INSTALL_DIR,
        "branch": "master"
    },
    {
        "repo_url": "https://github.com/platform9/express-cli.git",
        "repo_name": "Express CLI",
        "install_dir": globals.EXPRESS_CLI_INSTALL_DIR,
        "branch": "master"
    },
    {
        "repo_url": "https://github.com/platform9/express-wizard.git",
        "repo_name": "Express Wizard",
        "install_dir": globals.EXPRESS_WIZARD_INSTALL_DIR,
        "branch": "master"
    }
]

# manage dependent repositories
sys.stdout.write("Validating Dependencies\n")
for repo in required_repos:
    flag_init_cli = False
    if not os.path.isdir(repo['install_dir']):
        sys.stdout.write("--> cloning: {}\n".format(repo['repo_url']))
        cmd = "git clone {} {}".format(repo['repo_url'], repo['install_dir'])
        exit_status, stdout = run_cmd(cmd)
        if not os.path.isdir(repo['install_dir']):
            fail("ERROR: failed to clone repository")
        if repo['repo_name'] == "Express CLI":
            flag_init_cli = True

    cmd = "cd {}; git fetch -a".format(repo['install_dir'])
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        fail("ERROR: failed to fetch branches (git fetch -)")

    current_branch = get_branch(repo['install_dir'])
    if current_branch != repo['branch']:
        sys.stdout.write("--> switching branches: {}\n".format(repo['branch']))
        if (checkout_git_branch(repo['branch'],repo['install_dir'])) == False:
            fail("ERROR: failed to checkout git branch: {}".format(repo['branch']))

    cmd = "cd {}; git pull origin {}".format(repo['install_dir'],repo['branch'])
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        cmd = "cd {}; git stash".format(repo['install_dir'])
        exit_status, stdout = run_cmd(cmd)
        if exit_status != 0:
            fail("ERROR: failed to pull latest code (git pull origin {})\n".format(repo['branch']))
        cmd = "cd {}; git pull origin {}".format(repo['install_dir'],repo['branch'])
        exit_status, stdout = run_cmd(cmd)
        if exit_status != 0:
            fail("ERROR: failed to pull latest code (git pull origin {})\n".format(repo['branch']))
 
    if flag_init_cli:
        sys.stdout.write("INFO: Initializing EXPRESS CLI\n")
        cmd = "cd {}; pip install -e .[test]".format(repo['install_dir'])
        exit_status, stdout = run_cmd(cmd)
        if exit_status != 0:
            for line in stdout:
                sys.stdout.write("{}\n".format(line))
            fail("INFO: {}: installation failed".format(repo['repo_name']))

# update path for module imports
if args.local:
    local_lib_path = "{}/pf9-wizard/lib".format(globals.HOME_DIR)
    sys.stdout.write("WARNING: using local libraries (located in {})".format(local_lib_path))
    sys.path.append(local_lib_path)
else:
    sys.path.append("{}/lib".format(globals.EXPRESS_WIZARD_INSTALL_DIR))

# perform import (from modules within dependent repos)
try:
    import du_utils,pmk_utils,resmgr_utils,reports,datamodel,user_io,interview,express_utils
except:
    except_str = str(sys.exc_info()[1])
    module_name = except_str.split(' ')[-1]
    fail("Failed to import module: {}".format(sys.exc_info()[1],module_name))

# invoke commandline options
if args.export:
    datamodel.export_region(args.export)
    sys.exit(0)

# main menu loop
menu_level0()

# exit cleanly
sys.exit(0)
