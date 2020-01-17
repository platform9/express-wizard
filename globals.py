"""Global Variable Defaults"""
from os.path import expanduser

# globals
HOME_DIR = "{}".format(expanduser("~"))
CONFIG_DIR = "{}/.pf9-wizard".format(expanduser("~"))
CONFIG_FILE = "{}/du.conf".format(CONFIG_DIR)
HOST_FILE = "{}/hosts.conf".format(CONFIG_DIR)
WIZARD_VENV = "{}/.pf9-wizard/wizard-venv/bin/activate".format(expanduser("~"))
WIZARD_PYTHON = "{}/.pf9-wizard/wizard-venv/bin/python".format(expanduser("~"))
CLUSTER_FILE = "{}/clusters.conf".format(CONFIG_DIR)
EXPRESS_REPO = "https://github.com/platform9/express.git"
EXPRESS_LOG_DIR = "{}/.pf9-wizard/pf9-express/log".format(expanduser("~"))
PF9_EXPRESS = "{}/.pf9-wizard/express/pf9-express".format(expanduser("~"))
PF9_EXPRESS_CONFIG_PATH = "{}/.pf9-wizard/express/pf9-express.conf".format(expanduser("~"))
EXPRESS_INSTALL_DIR = "{}/express".format(CONFIG_DIR)
EXPRESS_CLI_INSTALL_DIR = "{}/express-cli".format(CONFIG_DIR)
EXPRESS_CLI_CONFIG_DIR = "{}/pf9/pf9-express/config/express.conf".format(expanduser("~"))
EXPRESS_CLI = "{}/.pf9-wizard/wizard-venv/bin/express".format(expanduser("~"))
EXPRESS_WIZARD_INSTALL_DIR = "{}/express-wizard".format(CONFIG_DIR)
EXPRESS_CLI_BRANCH = "tomchris/restructure"
EXPRESS_WIZARD_BRANCH = "master"
EXPRESS_BRANCH = "master"
