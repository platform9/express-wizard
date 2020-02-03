"""libs/help.py"""
import os
import sys
import ConfigParser
import globals

class Help:
    """Standardized help strings"""

    help_config = ConfigParser.ConfigParser()

    def __init__(self):
        try:
            self.help_config.read(globals.HELP_FILE)
        except:
            sys.stdout.write("ERROR: failed to initialize help subsystem, failed to open: {}".format(globals.HELP_FILE))
            sys.exit(1)

    def host_interview(self,question):
        help_strings = {
            "host-type": self.help_config.get('host_interview', 'host-type'),
            "Hostname": self.help_config.get('host_interview', 'hostname'),
            "host-template": self.help_config.get('host_interview', 'host-template')
        }

        if not question in help_strings:
            return("ERROR: host_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])


    def cluster_interview(self,question):
        help_strings = {
            "cluster-name": self.help_config.get('cluster_interview', 'cluster-name'),
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
            "role-profile-name": self.help_config.get('host_profile_interview', 'role-profile-name')
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
            "role-k8s-node-type": self.help_config.get('role_profile_interview', 'role-k8s-node-type')
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
            "auth-profile-key": self.help_config.get('auth_profile_interview', 'auth-profile-key')
        }

        if not question in help_strings:
            return("ERROR: auth_profile_interview.help_strings missing key: {}".format(question))
        else:
            return(help_strings[question])

