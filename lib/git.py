
def get_branch(install_dir):
    """get current branch from a git repo"""
    if not os.path.isdir(install_dir):
        return None

    cmd = "cd {} && git symbolic-ref --short -q HEAD".format(install_dir)
    exit_status, stdout = run_cmd(cmd)
    if exit_status != 0:
        return None

    return stdout[0].strip()


def checkout_git_branch(branch_name, install_dir):
    """checkout a branch on a git repo"""
    cmd = "cd {} && git checkout {}".format(install_dir, branch_name)
    exit_status, stdout = run_cmd(cmd)

    current_branch = get_branch(install_dir)
    if current_branch != branch_name:
        return False

    return True

def define_repos():
    """define dependent repositories"""
    if args.branch:
        globals.EXPRESS_WIZARD_BRANCH = args.branch[0]
    if args.branch_express:
        globals.EXPRESS_BRANCH = args.branch_express[0]
    if args.branch_cli:
        globals.EXPRESS_CLI_BRANCH = args.branch_cli[0]

    required_repos = [
        {
            "repo_url": globals.EXPRESS_REPO,
            "repo_name": "Express",
            "install_dir": globals.EXPRESS_INSTALL_DIR,
            "branch": globals.EXPRESS_BRANCH
        },
        {
            "repo_url": "https://github.com/platform9/express-cli.git",
            "repo_name": "Express CLI",
            "install_dir": globals.EXPRESS_CLI_INSTALL_DIR,
            "branch": globals.EXPRESS_CLI_BRANCH
        },
        {
            "repo_url": "https://github.com/platform9/express-wizard.git",
            "repo_name": "Express Wizard",
            "install_dir": globals.EXPRESS_WIZARD_INSTALL_DIR,
            "branch": globals.EXPRESS_WIZARD_BRANCH

def manage_repo():
   """manage dependent repositories"""
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
            if (checkout_git_branch(repo['branch'], repo['install_dir'])) == False:
                fail("ERROR: failed to checkout git branch: {}".format(repo['branch']))

        cmd = "cd {}; git pull origin {}".format(repo['install_dir'], repo['branch'])
        exit_status, stdout = run_cmd(cmd)
        if exit_status != 0:
            cmd = "cd {}; git stash".format(repo['install_dir'])
            exit_status, stdout = run_cmd(cmd)
            if exit_status != 0:
                fail("ERROR: failed to pull latest code (git pull origin {})\n".format(repo['branch']))
            cmd = "cd {}; git pull origin {}".format(repo['install_dir'], repo['branch'])
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
#sys.path.append("{}/lib".format(globals.EXPRESS_WIZARD_INSTALL_DIR))
