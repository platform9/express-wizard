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
    ap.add_argument("--skipActions", "-s", help = "Skip actions when importing region", action = "store_true")
    ap.add_argument('--jsonImport', "-j", help="Path to import file (JSON format, see '--export' function)", required=False)
    ap.add_argument("--export", "-e", help = "Name of region to export", required = False, nargs = 1)
    ap.add_argument("--encryptionKey", "-k", help = "Encryption key for decrytping secure data", required = False, nargs = 1)
    ap.add_argument("--debug", "-d", help = "Debug Mode", action = "store", nargs = 1)
    return ap.parse_args()


def dump_text_file(target_file):
    try:
        target_fh = open(target_file, 'r')
        title = "  START OF: {}  ".format(target_file)
        sys.stdout.write("\n{}\n".format(title.center(globals.terminal_width, '*')))
        sys.stdout.write(target_fh.read())
        footer = "  END OF: {}  ".format(target_file)
        sys.stdout.write("{}\n".format(footer.center(globals.terminal_width, '*')))
        target_fh.close()
    except:
        sys.stdout.write("ERROR: failed to open file: {}".format(target_file))


def view_log(log_files):
    # intialize help
    help = Help()

    cnt = 1
    allowed_values = ['q']
    for log_file in log_files:
        sys.stdout.write("{}. {}\n".format(cnt, log_file))
        allowed_values.append(str(cnt))
        cnt += 1
    user_input = user_io.read_kbd("Select Log", allowed_values, '', True, True, help.menu_interview("select-log"))
    if user_input != "q":
        idx = int(user_input) - 1
        target_log = log_files[idx]
        target_log_path = "{}/{}".format(globals.EXPRESS_LOG_DIR, target_log)
        dump_text_file(target_log_path)


def get_logs():
    MAX_LOGS = 10
    log_files = []
    cnt = 0
    if not os.path.isdir(globals.EXPRESS_LOG_DIR):
        return log_files

    for r, d, f in os.walk(globals.EXPRESS_LOG_DIR):
        # traverse list in reverse order (to show newest logs first)
        for file in f[::-1]:
            if cnt >= MAX_LOGS:
                break

            if file == ".keep":
                continue
            log_files.append(file)
            cnt += 1

    return log_files


def view_inventory(du, host_entries):
    express_inventory = express_utils.build_express_inventory(du, host_entries)
    if express_inventory:
        dump_text_file(express_inventory)
    else:
        sys.stdout.write("ERROR: failed to build inventory file: {}".format(express_inventory))


def action_header(title):
    title = "  {}  ".format(title)
    sys.stdout.write("\n{}\n".format(title.center(globals.terminal_width, '*')))


def display_menu3():
    sys.stdout.write("\n***************************************************\n")
    sys.stdout.write("**              -- Reports Menu --               **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Regions\n")
    sys.stdout.write("2. Clusters\n")
    sys.stdout.write("3. Hosts\n")
    sys.stdout.write("4. Auth Profiles\n")
    sys.stdout.write("5. Bond Profiles\n")
    sys.stdout.write("6. Role Profiles\n")
    sys.stdout.write("7. Host Templates\n")
    sys.stdout.write("8. PF9-Express Inventory\n")
    sys.stdout.write("9. Onboarding Logs\n")
    sys.stdout.write("***************************************************\n")


def display_menu2():
    sys.stdout.write("\n***************************************************\n")
    sys.stdout.write("**              - Profile Menu --                **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Manage Auth Profiles\n")
    sys.stdout.write("2. Manage Bond Profiles\n")
    sys.stdout.write("3. Manage Roles Profiles\n")
    sys.stdout.write("4. Manage Host Templates (Auth + Bond + Role)\n")
    sys.stdout.write("***************************************************\n")


def display_menu1():
    sys.stdout.write("\n***************************************************\n")
    sys.stdout.write("**            -- Maintenance Menu --             **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Delete Region\n")
    sys.stdout.write("2. Delete Host\n")
    sys.stdout.write("3. Delete Cluster\n")
    sys.stdout.write("***************************************************\n")


def display_menu0():
    sys.stdout.write("\n***************************************************\n")
    sys.stdout.write("**           Platform9 Express Wizard            **\n")
    sys.stdout.write("**               -- Main Menu --                 **\n")
    sys.stdout.write("***************************************************\n")
    sys.stdout.write("1. Manage Regions\n")
    sys.stdout.write("2. Manage Clusters\n")
    sys.stdout.write("3. Manage Hosts\n")
    sys.stdout.write("4. Manage Profiles\n")
    sys.stdout.write("5. Onboard Regions\n")
    sys.stdout.write("6. Reports\n")
    sys.stdout.write("7. Maintenance\n")
    sys.stdout.write("***************************************************\n")


def menu_level3():
    # intialize help
    help = Help()

    user_input = ""
    while not user_input in ['q', 'Q']:
        display_menu3()
        user_input = user_io.read_kbd("Enter Selection ('h' for help)", [], '', True, True, help.menu_interview("menu3"))
        if user_input == '1':
            action_header("SHOW REGION")
            selected_du = interview.select_du("Enter Region to Display")
            if selected_du:
                du_entries = datamodel.get_configs(selected_du['url'])
                reports.report_du_info(du_entries)
                host_entries = datamodel.get_hosts(selected_du['url'])
                reports.report_host_info(host_entries)
                if selected_du['du_type'] in ['Kubernetes', 'KVM/Kubernetes']:
                    cluster_entries = datamodel.get_clusters(selected_du['url'])
                    reports.report_cluster_info(cluster_entries)
        elif user_input == '2':
            sys.stdout.write("\nNot Implemented\n")
        elif user_input == '3':
            sys.stdout.write("\nNot Implemented\n")
        elif user_input == '4':
            auth_entries = datamodel.get_auth_profiles()
            reports.report_auth_profiles(auth_entries)
        elif user_input == '5':
            bond_entries = datamodel.get_bond_profiles()
            reports.report_bond_profiles(bond_entries)
        elif user_input == '6':
            role_entries = datamodel.get_role_profiles()
            reports.report_role_profiles(role_entries)
        elif user_input == '7':
            host_profile_entries = datamodel.get_host_profiles()
            reports.report_host_profiles(host_profile_entries)
        elif user_input == '8':
            selected_du = interview.select_du("Enter Region To Display inventory File")
            if selected_du:
                host_entries = datamodel.get_hosts(selected_du['url'])
                view_inventory(selected_du, host_entries)
        elif user_input == '9':
            log_files = get_logs()
            if len(log_files) == 0:
                sys.stdout.write("\nNo Logs Found")
            else:
                view_log(log_files)
        elif user_input in ['q', 'Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")


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
            selected_du = interview.select_du("Select Region To Delete")
            if selected_du:
                datamodel.delete_du(selected_du)
                datamodel.delete_du_host(selected_du)
        elif user_input == '2':
            selected_du = interview.select_du("Select Region (that contains the host you want to delete)")
            if selected_du:
                du_hosts = datamodel.get_hosts(selected_du['url'])
                if du_hosts:
                    host_list = []
                    for h in du_hosts:
                        host_list.append(h['hostname'])
                    menu_selection = interview.display_menu("HOSTS", "Select Host to Delete", host_list, '', help.menu_interview("menu0"))
                    if not menu_selection in [-1,-2]:
                        datamodel.delete_du_host(selected_du, du_hosts[menu_selection])
                else:
                    sys.stdout.write("\n--- INFO: no hosts found in this region ---\n\n")
        elif user_input == '3':
            selected_cluster = interview.select_du("Select Region (that contains the cluster you want to delete)")
            if selected_cluster:
                du_clusters = datamodel.get_clusters(selected_cluster['url'])
                if du_clusters:
                    cluster_list = []
                    for c in du_clusters:
                        cluster_list.append(c['name'])
                    menu_selection = interview.display_menu("CLUSTERS", "Select Cluster to Delete", cluster_list, '', help.menu_interview("menu0"))
                    if not menu_selection in [-1,-2]:
                        datamodel.delete_du_cluster(selected_cluster, du_clusters[menu_selection])
                else:
                    sys.stdout.write("\n--- INFO: no clusters found in this region ---\n\n")
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
            action_header("MANAGE CLUSTERS")
            selected_du = interview.select_du("Select Region To Add Cluster To", ['Kubernetes', 'KVM/Kubernetes'])
            if selected_du:
                new_cluster = interview.add_cluster(selected_du)
        elif user_input == '3':
            action_header("MANAGE HOSTS")
            selected_du = interview.select_du("Select Region To Add Host To")
            if selected_du:
                flag_more_hosts = True
                while flag_more_hosts:
                    new_host = interview.add_host(selected_du)
                    user_input = user_io.read_kbd("\nAdd Another Host?", ['y','n'], 'y', True, True, help.menu_interview("add-another-host"))
                    if user_input in ['n']:
                        flag_more_hosts = False
        elif user_input == '4':
            menu_level2()
        elif user_input == '5':
            action_header("ONBOARD HOSTS")
            selected_du = interview.select_du("Select Region To Onboard Hosts To")
            if selected_du:
                if selected_du['du_type'] == "Kubernetes":
                    sys.stdout.write("\nKubernetes Region: onboarding K8s nodes\n")
                    express_utils.run_express_cli(selected_du)
                    user_input = user_io.read_kbd("\nWould you like to run Region Discovery?", ['y','n'], 'y', True, True, help.menu_interview("run-region-discovery"))
                    if user_input == 'y':
                        datamodel.discover_region(selected_du)
                elif selected_du['du_type'] == "KVM":
                    sys.stdout.write("\nKVM Region: onboarding KVM hypervisors\n")
                    host_entries = datamodel.get_hosts(selected_du['url'])
                    express_utils.run_express(selected_du, host_entries)
                    user_input = user_io.read_kbd("\nWould you like to run Region Discovery?", ['y','n'], 'y', True, True, help.menu_interview("run-region-discovery"))
                    if user_input == 'y':
                        datamodel.discover_region(selected_du)
        elif user_input == '6':
            menu_level3()
        elif user_input == '7':
            menu_level1()
        elif user_input == 'cl':
            os.system('clear')
        elif user_input in ['q', 'Q']:
            None
        else:
            sys.stdout.write("ERROR: Invalid Selection (enter 'q' to quit)\n")

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

        # import standard configurations
        datamodel.import_region(globals.PLATFORM_DEFAULT_IMPORTFILE, True)

        if not args.jsonImport:
            sys.exit(0)

    # export datamodel
    if args.export:
        datamodel.export_region(args.export)
        sys.exit(0)
    if args.encryptionKey:
        # remove keyfile (if exists)
        if os.path.isfile(globals.ENCRYPTION_KEY_FILE):
            try:
                os.remove(globals.ENCRYPTION_KEY_FILE)
            except:
                sys.stdout.write("ERROR: failed to remove keyfile: {}".format(globals.ENCRYPTION_KEY_FILE))
                sys.exit(1)

        # write user-supplied encryption key to keyfile
        try:
            data_file_fh = open(globals.ENCRYPTION_KEY_FILE, "w")
            data_file_fh.write("{}".format(args.encryptionKey[0]))
            data_file_fh.close()
        except:
            sys.stdout.write("ERROR: failed to initialize keyfile for encryption: {}".format(globals.ENCRYPTION_KEY_FILE))
            sys.exit(1)
    if args.jsonImport:
        datamodel.import_region(args.jsonImport, args.skipActions)
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
