"""Global Variable Defaults"""
from os.path import expanduser

# globals
PF9_DIR = "{}/.pf9".format(expanduser("~"))
CONFIG_DIR = "{}/db".format(PF9_DIR)
CONFIG_FILE = "{}/du.conf".format(CONFIG_DIR)
HOST_FILE = "{}/hosts.conf".format(CONFIG_DIR)
CLUSTER_FILE = "{}/clusters.conf".format(CONFIG_DIR)

PF9_VENV = "{}/pf9-venv".format(PF9_DIR)
WIZARD_VENV = "{}/bin/activate".format(PF9_VENV)
WIZARD_PYTHON = "{}/bin/python".format(PF9_VENV)

SRC_DIR = "{}/src".format(PF9_DIR)
EXPRESS_REPO = "https://github.com/platform9/express.git"
EXPRESS_LOG_DIR = "{}/db/express/pf9-express/log".format(PF9_DIR)
PF9_EXPRESS = "{}/db/express/pf9-express".format(PF9_DIR)
PF9_EXPRESS_CONFIG_PATH = "{}/db/express/pf9-express.conf".format(PF9_DIR)
EXPRESS_INSTALL_DIR = "{}/db/express".format(PF9_DIR)
EXPRESS_CLI_INSTALL_DIR = "{}/express-cli".format(CONFIG_DIR)
EXPRESS_CLI_CONFIG_DIR = "{}/pf9/pf9-express/config/express.conf".format(expanduser("~"))
EXPRESS_CLI = "{}/.pf9-wizard/wizard-venv/bin/express".format(expanduser("~"))
EXPRESS_WIZARD_INSTALL_DIR = "{}/express-wizard".format(CONFIG_DIR)
EXPRESS_CLI_BRANCH = "tomchris/restructure"
EXPRESS_WIZARD_BRANCH = "master"
EXPRESS_BRANCH = "master"
ENCRYPTION_KEY_FILE = "{}/.keyfile".format(CONFIG_DIR)
