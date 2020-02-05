####################################################################################################
## PF9-Wizard | Onboarding Tool for Platform9
## Copyright(c) 2019 Platform9 Systems, Inc.
##
## (. ~/.pf9-wizard/wizard-venv/bin/activate && python wizard.py -l)
## (. ~/.pf9-wizard/wizard-venv/bin/activate && python wizard.py -l -e <du-url>)
## (. ~/.pf9-wizard/wizard-venv/bin/activate && python wizard.py -l -j <export-file>)
## (. ~/.pf9-wizard/wizard-venv/bin/activate && python ./wizard.py --test --local --debug 2)
####################################################################################################
import os
import sys
####################################################################################################
# early globals/functions
def fail(m=None):
    sys.stdout.write("ASSERT: {}\n".format(m))
    sys.exit(1)

def debug(m=None):
    sys.stdout.write("DEBUG: {}\n".format(m))
# validate python version
if not sys.version_info[0] in (2, 3):
    fail("Unsupported Python Version: {}\n".format(sys.version_info[0]))

####################################################################################################
# module imports
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, 'lib')))

try:
    import globals, urllib3, requests, json, prettytable, signal, getpass, argparse, subprocess, time
    import du_utils, pmk_utils, resmgr_utils, reports, datamodel, interview, express_utils, user_io
    from help_messages import Help
except:
    debug("EXCEPT: {}".format(sys.exc_info()))
    except_str = str(sys.exc_info()[1])
    module_name = except_str.split(' ')[-1]
    fail("Failed to import python module: {}".format(module_name))

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####################################################################################################
# functions
def _parse_args():
    ap = argparse.ArgumentParser(sys.argv[0], formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--init", "-i",  help = "Initialize Configuration (delete all regions/hosts)", action="store_true")
    ap.add_argument("--local", "-l", help = "Use local libraries (for development only)", action="store_true")
    ap.add_argument("--test", "-t", help = "Test Express-Wizard Build and Install", action = "store_true")
    ap.add_argument('--jsonImport', "-j", help="Path to import file (JSON format, see '--export' function)", required=False)
    ap.add_argument("--export", "-e", help = "Name of region to export", required = False, nargs = 1)
    ap.add_argument("--debug", "-d", help = "Debug Mode", action = "store", nargs = 1)
    return ap.parse_args()


def dump_var(target_var):
    from inspect import getmembers
    from pprint import pprint
    pprint(getmembers(target_var))


def run_cmd(cmd):
    cmd_stdout = ""
    tmpfile = "/tmp/pf9.{}.tmp".format(os.getppid())
    cmd_exitcode = os.system("{} > {} 2>&1".format(cmd, tmpfile))

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
    try:
        target_fh = open(target_file, 'r')
        title = "  START OF: {}  ".format(target_file)
        sys.stdout.write("\n{}".format(title.center(globals.terminal_width, '*')))
        sys.stdout.write(target_fh.read())
        footer = "  END OF: {}  ".format(target_file)
        sys.stdout.write("{}\n".format(footer.center(globals.terminal_width, '*')))
        target_fh.close()
    except:
        sys.stdout.write("ERROR: failed to open file: {}".format(target_file))


def view_log(log_files):
    cnt = 1
    allowed_values = ['q']
    for log_file in log_files:
        sys.stdout.write("{}. {}\n".format(cnt, log_file))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("Select Log", allowed_values, '', True, True, '')
    if user_input != "q":
        idx = int(user_input) - 1
        target_log = log_files[idx]
        target_log_path = "{}/{}".format(globals.EXPRESS_LOG_DIR, target_log)
        dump_text_file(target_log_path)


def get_logs():
    log_files = []
    if not os.path.isdir(globals.EXPRESS_LOG_DIR):
        return log_files

    for r, d, f in os.walk(globals.EXPRESS_LOG_DIR):
        for file in f:
            if file == ".keep":
                continue
            log_files.append(file)

    return log_files


def view_inventory(du, host_entries):
    express_inventory = express_utils.build_express_inventory(du, host_entries)
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
            pprint(db_json)


def action_header(title):
    title = "  {}  ".format(title)
    sys.stdout.write("\n{}".format(title.center(globals.terminal_width, '*')))


def display_menu2():
    sys.stdout.write("\n***************************************************\n")
    sys.stdout.write("**           Platform9 Express Wizard            **\n")
    sys.stdout.write("**              - Profile Menu --                **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Manage Auth Profiles\n")
    sys.stdout.write("2. Manage Bond Profiles\n")
    sys.stdout.write("3. Manage Roles Profiles\n")
    sys.stdout.write("4. Manage Host Templates (Auth + Bond + Role)\n")
    sys.stdout.write("5. Display Auth Profiles\n")
    sys.stdout.write("6. Display Bond Profiles\n")
    sys.stdout.write("7. Display Role Profiles\n")
    sys.stdout.write("8. Display Host Templates\n")
    sys.stdout.write("***************************************************\n")


def display_menu1():
    sys.stdout.write("\n***************************************************\n")
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
    sys.stdout.write("\n***************************************************\n")
    sys.stdout.write("**           Platform9 Express Wizard            **\n")
    sys.stdout.write("**               -- Main Menu --                 **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Manage/Discover Regions\n")
    sys.stdout.write("2. Manage Profiles\n")
    sys.stdout.write("3. Manage Clusters\n")
    sys.stdout.write("4. Manage Hosts\n")
    sys.stdout.write("5. Onboard Host (to Region)\n")
    sys.stdout.write("6. Show Regions\n")
    sys.stdout.write("7. Maintenance\n")
    sys.stdout.write("***************************************************\n")


def menu_level2():
    # intialize help
    help = Help()

    user_input = ""
    while not user_input in ['q', 'Q']:
        display_menu2()
        user_input = user_io.read_kbd("Enter Selection ('h' for help)", [], '', True, True, help.menu_interview("menu2"))
        if user_input == '1':
            action_header("MANAGE AUTHORIZATION PROFILES")
            selected_profile = interview.add_edit_auth_profile()
            if selected_profile != None:
                if selected_profile == "define-new-auth-profile":
                    target_profile = None
                else:
                    target_profile = selected_profile
                interview.add_auth_profile(target_profile)
        elif user_input == '2':
            action_header("MANAGE BOND PROFILES")
            selected_profile = interview.add_edit_bond_profile()
            if selected_profile != None:
                if selected_profile == "define-new-bond-profile":
                    target_profile = None
                else:
                    target_profile = selected_profile
                interview.add_bond_profile(target_profile)
        elif user_input == '3':
            action_header("MANAGE ROLE PROFILES")
            selected_profile = interview.add_edit_role_profile()
            if selected_profile != None:
                if selected_profile == "define-new-role-profile":
                    target_profile = None
                else:
                    target_profile = selected_profile
                interview.add_role_profile(target_profile)
        elif user_input == '4':
            action_header("MANAGE HOST TEMPLATES")
            selected_profile = interview.add_edit_host_profile()
            if selected_profile != None:
                if selected_profile == "define-new-host-profile":
                    target_profile = None
                else:
                    target_profile = selected_profile
                interview.add_host_profile(target_profile)
        elif user_input == '5':
            auth_entries = datamodel.get_auth_profiles()
            reports.report_auth_profiles(auth_entries)
        elif user_input == '6':
            bond_entries = datamodel.get_bond_profiles()
            reports.report_bond_profiles(bond_entries)
        elif user_input == '7':
            role_entries = datamodel.get_role_profiles()
            reports.report_role_profiles(role_entries)
        elif user_input == '8':
            host_profile_entries = datamodel.get_host_profiles()
            reports.report_host_profiles(host_profile_entries)
        elif user_input in ['q', 'Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")


def menu_level1():
    # intialize help
    help = Help()

    user_input = ""
    while not user_input in ['q', 'Q']:
        display_menu1()
        user_input = user_io.read_kbd("Enter Selection ('h' for help)", [], '', True, True, help.menu_interview("menu1"))
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
                    view_config(selected_du)
        elif user_input == '7':
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    host_entries = datamodel.get_hosts(selected_du['url'])
                    view_inventory(selected_du, host_entries)
        elif user_input == '8':
            log_files = get_logs()
            if len(log_files) == 0:
                sys.stdout.write("\nNo Logs Found")
            else:
                view_log(log_files)
        elif user_input in ['q', 'Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")


def menu_level0():
    # intialize help
    help = Help()

    user_input = ""
    while not user_input in ['q', 'Q']:
        display_menu0()
        user_input = user_io.read_kbd("Enter Selection ('h' for help)", [], '', True, True, help.menu_interview("menu0"))
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
            menu_level2()
        elif user_input == '3':
            action_header("MANAGE CLUSTERS")
            sys.stdout.write("\nSelect Region to add Cluster to:")
            selected_du = interview.select_du(['Kubernetes', 'KVM/Kubernetes'])
            if selected_du:
                if selected_du != "q":
                    new_cluster = interview.add_cluster(selected_du)
        elif user_input == '4':
            action_header("MANAGE HOSTS")
            sys.stdout.write("\nSelect Region to Add Host To:")
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    flag_more_hosts = True
                    while flag_more_hosts:
                        new_host = interview.add_host(selected_du)
                        user_input = user_io.read_kbd("\nAdd Another Host?", ['y', 'n'], 'y', True, True, '')
                        if user_input == "n":
                            flag_more_hosts = False
        elif user_input == '5':
            action_header("ONBOARD HOSTS")
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    if selected_du['du_type'] == "Kubernetes":
                        sys.stdout.write("\nKubernetes Region: onboarding K8s nodes\n")
                        express_utils.run_express_cli(selected_du)
                    elif selected_du['du_type'] == "KVM":
                        sys.stdout.write("\nKVM Region: onboarding KVM hypervisors\n")
                        host_entries = datamodel.get_hosts(selected_du['url'])
                        express_utils.run_express(selected_du, host_entries)
        elif user_input == '6':
            action_header("SHOW REGION")
            selected_du = interview.select_du()
            if selected_du:
                if selected_du != "q":
                    du_entries = datamodel.get_configs(selected_du['url'])
                    reports.report_du_info(du_entries)
                    host_entries = datamodel.get_hosts(selected_du['url'])
                    reports.report_host_info(host_entries)
                    if selected_du['du_type'] in ['Kubernetes', 'KVM/Kubernetes']:
                        cluster_entries = datamodel.get_clusters(selected_du['url'])
                        reports.report_cluster_info(cluster_entries)
        elif user_input == '7':
            menu_level1()
        elif user_input in ['q', 'Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")


def ssh_validate_login(du_metadata, host_ip):
    if du_metadata['auth_type'] == "simple":
        return False
        cmd = "ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no {}@{} 'echo 201'".format(du_metadata['auth_ssh_key'], du_metadata['auth_username'], host_ip)
    elif du_metadata['auth_type'] == "sshkey":
        cmd = "ssh -o StrictHostKeyChecking, no -i {} {}@{} 'echo 201'".format(du_metadata['auth_ssh_key'], du_metadata['auth_username'], host_ip)
        exit_status, stdout = run_cmd(cmd)
        if exit_status == 0:
            return True
        else:
            return False

    return False


## main
def main():
    args = _parse_args()

    # IF args.local was passed change CONFIG_DIR to 
    #    parent dir of directory wizard.py was launched from
    if args.local:
        globals.CONFIG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        debug("CONFIG_DIR: {}".format(globals.CONFIG_DIR)) 
    # perform initialization (if invoked with '--init')
    if args.init:
        sys.stdout.write("INFO: initializing configuration\n")
        if os.path.isfile(globals.HOST_FILE):
            os.remove(globals.HOST_FILE)
        if os.path.isfile(globals.CONFIG_FILE):
            os.remove(globals.CONFIG_FILE)
        if os.path.isfile(globals.CLUSTER_FILE):
            os.remove(globals.CLUSTER_FILE)

        if os.path.isfile(globals.AUTH_PROFILE_FILE):
            os.remove(globals.AUTH_PROFILE_FILE)
        if os.path.isfile(globals.BOND_PROFILE_FILE):
            os.remove(globals.BOND_PROFILE_FILE)
        if os.path.isfile(globals.ROLE_PROFILE_FILE):
            os.remove(globals.ROLE_PROFILE_FILE)
        if os.path.isfile(globals.HOST_PROFILE_FILE):
            os.remove(globals.HOST_PROFILE_FILE)

    # export datamodel
    if args.export:
        datamodel.export_region(args.export)
        sys.exit(0)
    if args.jsonImport:
        datamodel.import_region(args.jsonImport)
        sys.exit(0)

    # If test is passed exit before menu_level0() temp until unittest
    if args.test:
        sys.exit(0)

    # main menu loop
    menu_level0()

    # exit cleanly
    sys.exit(0)

if __name__ == "__main__":
    main()
