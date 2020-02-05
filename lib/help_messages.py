"""libs/help.py"""
import os
import sys
import globals
try:
    import ConfigParser
except ImportError:
    import configparser

class Help:
    """Standardized help strings"""

    if sys.version_info[0] == 2:
        help_config = ConfigParser.ConfigParser()
    else:
        help_config = configparser.ConfigParser()

    def __init__(self):
        try:
            self.help_config.read(globals.HELP_FILE)
        except Exception as ex:
            sys.stdout.write("ERROR: failed to initialize help subsystem, failed to parse: {}\n".format(globals.HELP_FILE))
            sys.stdout.write("ConfigParser.Exception: {}\n".format(ex.message))
            sys.exit(1)

    def host_interview(self,question):
        help_strings = {
            "host-type": self.help_config.get('host_interview', 'host-type'),
            "Hostname": self.help_config.get('host_interview', 'hostname'),
            "host-template": self.help_config.get('host_interview', 'host-template'),
            "primary-ip": self.help_config.get('host_interview', 'primary-ip')
        }

        if not question in help_strings:
            return("ERROR: host_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def onboard_interview(self,question):
        help_strings = {
            "attach-masters": self.help_config.get('onboard_interview', 'attach-masters'),
            "select-masters": self.help_config.get('onboard_interview', 'select-masters'),
            "attach-workers": self.help_config.get('onboard_interview', 'attach-workers'),
            "select-workers": self.help_config.get('onboard_interview', 'select-workers'),
            "express-prereqs": self.help_config.get('onboard_interview', 'express-prereqs'),
            "run-express": self.help_config.get('onboard_interview', 'run-express'),
            "run-express-cli": self.help_config.get('onboard_interview', 'run-express-cli'),
            "select-inventory": self.help_config.get('onboard_interview', 'select-inventory'),
            "custom-inventory": self.help_config.get('onboard_interview', 'custom-inventory'),
            "role-assignment": self.help_config.get('onboard_interview', 'role-assignment')
        }

        if not question in help_strings:
            return("ERROR: onboard_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def cluster_interview(self,question):
        help_strings = {
            "cluster-name": self.help_config.get('cluster_interview', 'cluster-name'),
            "select-cluster": self.help_config.get('cluster_interview', 'select-cluster'),
            "containers-cidr": self.help_config.get('cluster_interview', 'containers-cidr'),
            "services-cird": self.help_config.get('cluster_interview', 'services-cird'),
            "master-vip": self.help_config.get('cluster_interview', 'master-vip'),
            "interface-name-vip": self.help_config.get('cluster_interview', 'interface-name-vip'),
            "ip-range-metallb": self.help_config.get('cluster_interview', 'ip-range-metallb'),
            "priviliged-mode": self.help_config.get('cluster_interview', 'priviliged-mode'),
            "enable-helm-catalog": self.help_config.get('cluster_interview', 'enable-helm-catalog'),
            "enable-master-workloads": self.help_config.get('cluster_interview', 'enable-master-workloads'),
            "select-cluster": self.help_config.get('cluster_interview', 'select-cluster')
        }

        if not question in help_strings:
            return("ERROR: cluster_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def host_profile_interview(self,question):
        help_strings = {
            "host-profile-name": self.help_config.get('host_profile_interview', 'host-profile-name'),
            "auth-profile-name": self.help_config.get('host_profile_interview', 'auth-profile-name'),
            "bond-profile-name": self.help_config.get('host_profile_interview', 'bond-profile-name'),
            "role-profile-name": self.help_config.get('host_profile_interview', 'role-profile-name'),
            "select-host-profile": self.help_config.get('host_profile_interview', 'select-host-profile'),
            "update-bond-profile": self.help_config.get('host_profile_interview', 'update-bond-profile')
        }

        if not question in help_strings:
            return("ERROR: host_profile_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def bond_profile_interview(self,question):
        help_strings = {
            "bond-profile-name": self.help_config.get('bond_profile_interview', 'bond-profile-name'),
            "bond-interface-name": self.help_config.get('bond_profile_interview', 'bond-interface-name'),
            "bond-mode": self.help_config.get('bond_profile_interview', 'bond-mode'),
            "bond-mtu": self.help_config.get('bond_profile_interview', 'bond-mtu'),
            "bond-members": self.help_config.get('bond_profile_interview', 'bond-members')
        }

        if not question in help_strings:
            return("ERROR: bond_profile_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def role_profile_interview(self,question):
        help_strings = {
            "role-profile-name": self.help_config.get('role_profile_interview', 'role-profile-name'),
            "role-du-host-type": self.help_config.get('role_profile_interview', 'role-du-host-type'),
            "role-pmo-glance": self.help_config.get('role_profile_interview', 'role-pmo-glance'),
            "role-pmo-cinder": self.help_config.get('role_profile_interview', 'role-pmo-cinder'),
            "role-pmo-designate": self.help_config.get('role_profile_interview', 'role-pmo-designate'),
            "role-k8s-node-type": self.help_config.get('role_profile_interview', 'role-k8s-node-type'),
            "update-role-profile": self.help_config.get('role_profile_interview', 'update-role-profile')
        }

        if not question in help_strings:
            return("ERROR: role_profile_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def auth_profile_interview(self,question):
        help_strings = {
            "auth-profile-name": self.help_config.get('auth_profile_interview', 'auth-profile-name'),
            "auth-profile-type": self.help_config.get('auth_profile_interview', 'auth-profile-type'),
            "auth-profile-username": self.help_config.get('auth_profile_interview', 'auth-profile-username'),
            "auth-profile-password": self.help_config.get('auth_profile_interview', 'auth-profile-password'),
            "auth-profile-key": self.help_config.get('auth_profile_interview', 'auth-profile-key'),
            "update-auth-profile": self.help_config.get('auth_profile_interview', 'update-auth-profile')
        }

        if not question in help_strings:
            return("ERROR: auth_profile_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def menu_interview(self,question):
        help_strings = {
            "menu0": self.help_config.get('menu_interview', 'menu0'),
            "menu1": self.help_config.get('menu_interview', 'menu1'),
            "menu2": self.help_config.get('menu_interview', 'menu2'),
            "select-log": self.help_config.get('menu_interview', 'select-log'),
            "add-another-host": self.help_config.get('menu_interview', 'add-another-host')
        }

        if not question in help_strings:
            return("ERROR: menu_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def region_interview(self,question):
        help_strings = {
            "add-region": self.help_config.get('region_interview', 'add-region'),
            "discover-region": self.help_config.get('region_interview', 'discover-region'),
            "select-region": self.help_config.get('region_interview', 'select-region'),
            "confirm-region-type": self.help_config.get('region_interview', 'confirm-region-type'),
            "validate-ssh-connectivity": self.help_config.get('region_interview', 'validate-ssh-connectivity'),
            "region-url": self.help_config.get('region_interview', 'region-url'),
            "region-type": self.help_config.get('region_interview', 'region-type'),
            "region-username": self.help_config.get('region_interview', 'region-username'),
            "region-password": self.help_config.get('region_interview', 'region-password'),
            "region-tentant": self.help_config.get('region_interview', 'region-tentant'),
            "region-branch": self.help_config.get('region_interview', 'region-branch'),
            "region-auth-type": self.help_config.get('region_interview', 'region-auth-type'),
            "region-ssh-username": self.help_config.get('region_interview', 'region-ssh-username'),
            "region-ssh-password": self.help_config.get('region_interview', 'region-ssh-password'),
            "region-ssh-key": self.help_config.get('region_interview', 'region-ssh-key'),
            "region-http-proxy": self.help_config.get('region_interview', 'region-http-proxy'),
            "region-dns": self.help_config.get('region_interview', 'region-dns'),
            "region-bond-if-name": self.help_config.get('region_interview', 'region-bond-if-name'),
            "region-bond-mode": self.help_config.get('region_interview', 'region-bond-mode'),
            "region-bond-mtu": self.help_config.get('region_interview', 'region-bond-mtu')
        }

        if not question in help_strings:
            return("ERROR: region_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])

