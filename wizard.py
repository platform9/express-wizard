####################################################################################################
## PF9-Wizard | Onboarding Tool for Platform9 
## Copyright(c) 2019 Platform9 Systems, Inc.
####################################################################################################
# To-Do:
# 1. Call Express CLI for PMK
# 2. Hierarchical/Scalable Data Model
# 3. Add Region : Improve error recovery when DU auth fails
####################################################################################################
import os
import sys
from os.path import expanduser
import du_utils
import pmk_utils
import resmgr_utils
import ssh_utils
import reports
import datamodel
import user_io
import interview
import express_utils

################################################################################
# early functions
def fail(m=None):
    sys.stdout.write("ASSERT: {}\n".format(m))
    sys.exit(1)

if not sys.version_info[0] in (2,3):
    fail("Unsupported Python Version: {}\n".format(sys.version_info[0]))

################################################################################
# module imports
try:
    import requests,urllib3,json,argparse,prettytable,signal,getpass,argparse,subprocess,time,pprint
except:
    except_str = str(sys.exc_info()[1])
    module_name = except_str.split(' ')[-1]
    fail("Failed to import module: {} (try running 'pip install {}')".format(sys.exc_info()[1],module_name))

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# input functions
def _parse_args():
    ap = argparse.ArgumentParser(sys.argv[0],formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--init", "-i", help="Initialize Configuration (delete all regions/hosts)", action="store_true")
    return ap.parse_args()


def dump_var(target_var):
    from inspect import getmembers
    from pprint import pprint
    pprint(getmembers(target_var))


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
        target_log_path = "{}/{}".format(EXPRESS_LOG_DIR,target_log)
        dump_text_file(target_log_path)


def get_logs():
    log_files = []
    if not os.path.isdir(EXPRESS_LOG_DIR):
        return(log_files)

    for r, d, f in os.walk(EXPRESS_LOG_DIR):
        for file in f:
            if file == ".keep":
                continue
            log_files.append(file)

    return(log_files)


def view_inventory(du, host_entries, CONFIG_DIR):
    express_inventory = express_utils.build_express_inventory(du,host_entries,CONFIG_DIR,CLUSTER_FILE)
    if express_inventory:
        dump_text_file(express_inventory)
    else:
        sys.stdout.write("ERROR: failed to build inventory file: {}".format(express_inventory))


def view_config(du,CONFIG_DIR):
    express_config = express_utils.build_express_config(du,CONFIG_DIR)
    if express_config:
        dump_text_file(express_config)
    else:
        sys.stdout.write("ERROR: failed to build configuration file: {}".format(express_config))


def dump_database(db_file):
    if os.path.isfile(db_file):
        with open(db_file) as json_file:
            db_json = json.load(json_file)
        pprint.pprint(db_json)


def action_header(title):
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
    sys.stdout.write("5. View Configuration File\n")
    sys.stdout.write("6. View Inventory File\n")
    sys.stdout.write("7. View Logs\n")
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
            selected_du = interview.select_du(CONFIG_DIR,CONFIG_FILE)
            if selected_du:
                if selected_du != "q":
                    datamodel.delete_du(selected_du,CONFIG_FILE)
        elif user_input == '2':
            sys.stdout.write("\nNot Implemented\n")
        elif user_input == '3':
            dump_database(CONFIG_FILE)
        elif user_input == '4':
            dump_database(HOST_FILE)
        elif user_input == '5':
            selected_du = interview.select_du(CONFIG_DIR,CONFIG_FILE)
            if selected_du:
                if selected_du != "q":
                    new_host = view_config(selected_du,CONFIG_DIR)
        elif user_input == '6':
            selected_du = interview.select_du(CONFIG_DIR,CONFIG_FILE)
            if selected_du:
                if selected_du != "q":
                    host_entries = datamodel.get_hosts(selected_du['url'],HOST_FILE)
                    new_host = view_inventory(selected_du, host_entries, CONFIG_DIR)
        elif user_input == '7':
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
    while not user_input in ['q','Q']:
        display_menu0()
        user_input = user_io.read_kbd("Enter Selection", [], '', True, True)
        if user_input == '1':
            action_header("MANAGE REGIONS")
            selected_du = interview.add_edit_du(CONFIG_DIR, CONFIG_FILE)
            if selected_du != None:
                if selected_du == "define-new-du":
                    target_du = None
                else:
                    target_du = selected_du
                new_du_list = interview.add_region(target_du,CONFIG_DIR,CONFIG_FILE,HOST_FILE,CLUSTER_FILE)
                if new_du_list:
                    reports.report_du_info(new_du_list,CONFIG_FILE,HOST_FILE)
        elif user_input == '2':
            action_header("MANAGE HOSTS")
            sys.stdout.write("\nSelect Region to add Host to:")
            selected_du = interview.select_du(CONFIG_DIR,CONFIG_FILE)
            if selected_du:
                if selected_du != "q":
                    flag_more_hosts = True
                    while flag_more_hosts:
                        new_host = interview.add_host(selected_du,HOST_FILE,CONFIG_DIR,CONFIG_FILE,CLUSTER_FILE)
                        user_input = user_io.read_kbd("\nAdd Another Host?", ['y','n'], 'n', True, True)
                        if user_input == "n":
                            flag_more_hosts = False
        elif user_input == '3':
            action_header("MANAGE CLUSTERS")
            sys.stdout.write("\nSelect Region to add Cluster to:")
            selected_du = interview.select_du(CONFIG_DIR,CONFIG_FILE)
            if selected_du:
                if selected_du != "q":
                    new_cluster = interview.add_cluster(selected_du,CONFIG_DIR,CLUSTER_FILE)
        elif user_input == '4':
            action_header("SHOW REGION")
            selected_du = interview.select_du(CONFIG_DIR,CONFIG_FILE)
            if selected_du:
                if selected_du != "q":
                    du_entries = datamodel.get_configs(CONFIG_FILE,selected_du['url'])
                    reports.report_du_info(du_entries,CONFIG_FILE,HOST_FILE)
                    host_entries = datamodel.get_hosts(selected_du['url'],HOST_FILE)
                    reports.report_host_info(host_entries,HOST_FILE,CONFIG_FILE)
                    if selected_du['du_type'] in ['Kubernetes','KVM/Kubernetes']:
                        cluster_entries = datamodel.get_clusters(selected_du['url'],CLUSTER_FILE)
                        reports.report_cluster_info(cluster_entries,CLUSTER_FILE)
        elif user_input == '5':
            action_header("ONBOARD HOSTS")
            selected_du = interview.select_du(CONFIG_DIR,CONFIG_FILE)
            if selected_du:
                if selected_du != "q":
                    host_entries = datamodel.get_hosts(selected_du['url'],HOST_FILE)
                    express_utils.run_express(selected_du,host_entries,EXPRESS_INSTALL_DIR,EXPRESS_REPO,CONFIG_DIR,PF9_EXPRESS,CLUSTER_FILE)
        elif user_input == '6':
            menu_level1()
        elif user_input in ['q','Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")

        if user_input != '7':
            sys.stdout.write("\n")


## main
args = _parse_args()

# globals
HOME_DIR = expanduser("~")
CONFIG_DIR = "{}/.pf9-wizard".format(HOME_DIR)
CONFIG_FILE = "{}/du.conf".format(CONFIG_DIR)
HOST_FILE = "{}/hosts.conf".format(CONFIG_DIR)
CLUSTER_FILE = "{}/clusters.conf".format(CONFIG_DIR)
EXPRESS_REPO = "https://github.com/platform9/express.git"
EXPRESS_INSTALL_DIR = "{}/.pf9-wizard/pf9-express".format(HOME_DIR)
EXPRESS_LOG_DIR = "{}/.pf9-wizard/pf9-express/log".format(HOME_DIR)
PF9_EXPRESS = "{}/.pf9-wizard/pf9-express/pf9-express".format(HOME_DIR)
MAX_WIDTH = 132

# perform initialization (if invoked with '--init')
if args.init:
    sys.stdout.write("INFO: initializing configuration\n")
    if os.path.isfile(HOST_FILE):
        os.remove(HOST_FILE)
    if os.path.isfile(CONFIG_FILE):
        os.remove(CONFIG_FILE)
    if os.path.isfile(CLUSTER_FILE):
        os.remove(CLUSTER_FILE)

# main menu loop
menu_level0()

# exit cleanly
sys.exit(0)
