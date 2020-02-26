{
  "actions": [
      {
          "operation": "discover-region",
          "region-name": "https://cs-integration-k8s01.platform9.horse"
      },
      {
          "operation": "onboard-region",
          "region-name": "https://cs-integration-k8s01.platform9.horse",
          "cluster-name": "ci-cluster01"
      },
      {
          "operation": "discover-region",
          "region-name": "https://cs-integration-k8s01.platform9.horse"
      }
  ],
  "region": {
    "username": "soleng",
    "auth_type": "sshkey",
    "bond_ifname": "",
    "bond_mode": "",
    "du_type": "Kubernetes",
    "auth_username": "centos",
    "tenant": "service",
    "dns_list": "",
    "password": "gAAAAABeQZmcLodSISuZWMCNjMJWOCTNiGZmTomWtWSx2TG7eFyd7qcVqdWt_ZQI3ozQiK-Eril2jj5_-cq6xeDRsyv9PHaoMQ==",
    "auth_password": "",
    "url": "https://cs-integration-k8s01.platform9.horse",
    "region": "k8s01",
    "region_proxy": "",
    "git_branch": "master",
    "auth_ssh_key": "<ssh-keypath>",
    "bond_mtu": ""
  },
  "clusters": [
    {
      "name": "ci-cluster01",
      "du_url": "https://cs-integration-k8s01.platform9.horse",
      "record_source": "User-Defined",
      "containers_cidr": "192.168.0.0/16",
      "services_cidr": "192.169.0.0/16",
      "master_vip_iface": "ens160",
      "master_vip_ipv4": "172.20.8.244",
      "metallb_cidr": "172.20.8.240-172.20.8.243",
      "app_catalog_enabled": 0,
      "allow_workloads_on_master": 0,
      "privileged": 1,
      "uuid": ""
    }
  ],
  "hosts": [
    {
      "hostname": "ci-k8s01",
      "du_url": "https://cs-integration-k8s01.platform9.horse",
      "du_type": "Kubernetes",
      "du_host_type": "kubernetes",
      "record_source": "User-Defined",
      "ip": "<ip-master01>",
      "fk_host_profile": "",
      "node_type": "master",
      "cluster_name": "ci-cluster01",
      "pf9-kube": "y",
      "nova": "n",
      "glance": "n",
      "cinder": "n",
      "designate": "n"
    },
    {
      "hostname": "ci-k8s02",
      "du_url": "https://cs-integration-k8s01.platform9.horse",
      "du_type": "Kubernetes",
      "du_host_type": "kubernetes",
      "record_source": "User-Defined",
      "ip": "<ip-master02>",
      "fk_host_profile": "",
      "node_type": "master",
      "cluster_name": "ci-cluster01",
      "pf9-kube": "y",
      "nova": "n",
      "glance": "n",
      "cinder": "n",
      "designate": "n"
    },
    {
      "hostname": "ci-k8s03",
      "du_url": "https://cs-integration-k8s01.platform9.horse",
      "du_type": "Kubernetes",
      "du_host_type": "kubernetes",
      "record_source": "User-Defined",
      "ip": "<ip-master03>",
      "fk_host_profile": "",
      "node_type": "master",
      "cluster_name": "ci-cluster01",
      "pf9-kube": "y",
      "nova": "n",
      "glance": "n",
      "cinder": "n",
      "designate": "n"
    },
    {
      "hostname": "ci-k8s04",
      "du_url": "https://cs-integration-k8s01.platform9.horse",
      "du_type": "Kubernetes",
      "du_host_type": "kubernetes",
      "record_source": "User-Defined",
      "ip": "<ip-worker01>",
      "fk_host_profile": "",
      "node_type": "worker",
      "cluster_name": "ci-cluster01",
      "pf9-kube": "y",
      "nova": "n",
      "glance": "n",
      "cinder": "n",
      "designate": "n"
    }
  ],
  "host-profiles": [
    {
      "fk_role_profile": "Hypervisor with Glance",
      "host_profile_name": "CentOS - Hypervisor",
      "fk_bond_profile": "CentOS Bond Config 1 (ALB)",
      "fk_auth_profile": "CentOS SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Hypervisor with Glance",
      "host_profile_name": "CentOS - Hypervisor w/Glance",
      "fk_bond_profile": "CentOS Bond Config 2 (Round-Robin)",
      "fk_auth_profile": "CentOS SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Hypervisor with Cinder",
      "host_profile_name": "CentOS - Hypervisor w/Cinder",
      "fk_bond_profile": "CentOS Bond Config 2 (Round-Robin)",
      "fk_auth_profile": "CentOS SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Hypervisor with Designate",
      "host_profile_name": "CentOS - Hypervisor w/Designate",
      "fk_bond_profile": "CentOS Bond Config 2 (Round-Robin)",
      "fk_auth_profile": "CentOS SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Kubernetes Master",
      "host_profile_name": "Centos - Kubernetes Master",
      "fk_bond_profile": "CentOS Bond Config 1 (ALB)",
      "fk_auth_profile": "CentOS SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Kubernetes Worker",
      "host_profile_name": "Centos - Kubernetes Worker",
      "fk_bond_profile": "CentOS Bond Config 1 (ALB)",
      "fk_auth_profile": "CentOS SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Hypervisor with Glance",
      "host_profile_name": "Ubuntu - Hypervisor",
      "fk_bond_profile": "Ubuntu Bond Config 1 (ALB)",
      "fk_auth_profile": "Ubuntu SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Hypervisor with Glance",
      "host_profile_name": "Ubuntu - Hypervisor w/Glance",
      "fk_bond_profile": "Ubuntu Bond Config 2 (Round-Robin)",
      "fk_auth_profile": "Ubuntu SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Hypervisor with Designate",
      "host_profile_name": "Ubuntu - Hypervisor w/Designate",
      "fk_bond_profile": "Ubuntu Bond Config 2 (Round-Robin)",
      "fk_auth_profile": "Ubuntu SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Hypervisor with Cinder",
      "host_profile_name": "Ubuntu - Hypervisor w/Cinder",
      "fk_bond_profile": "Ubuntu Bond Config 2 (Round-Robin)",
      "fk_auth_profile": "Ubuntu SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Kubernetes Master",
      "host_profile_name": "Ubuntu - Kubernetes Master",
      "fk_bond_profile": "Ubuntu Bond Config 1 (ALB)",
      "fk_auth_profile": "Ubuntu SSH Access (Key-based)"
    },
    {
      "fk_role_profile": "Kubernetes Worker",
      "host_profile_name": "Ubuntu - Kubernetes Worker",
      "fk_bond_profile": "Ubuntu Bond Config 1 (ALB)",
      "fk_auth_profile": "Ubuntu SSH Access (Key-based)"
    }
  ],
  "bond-profiles": [
    {
      "bond_ifname": "bond0",
      "bond_name": "CentOS Bond Config 1 (ALB)",
      "bond_members": "ens160 ens192",
      "bond_mode": 6,
      "bond_mtu": "9000"
    },
    {
      "bond_ifname": "bond0",
      "bond_name": "CentOS Bond Config 2 (Round-Robin)",
      "bond_members": "ens160 ens192",
      "bond_mode": 0,
      "bond_mtu": "9000"
    },
    {
      "bond_ifname": "bond0",
      "bond_name": "Ubuntu Bond Config 1 (ALB)",
      "bond_members": "eth0 eth1",
      "bond_mode": 6,
      "bond_mtu": "9000"
    },
    {
      "bond_ifname": "bond0",
      "bond_name": "Ubuntu Bond Config 2 (Round-Robin)",
      "bond_members": "eth0 eth1",
      "bond_mode": 0,
      "bond_mtu": "9000"
    }
  ],
  "role-profiles": [
    {
      "pf9-kube": "",
      "nova": "y",
      "node_type": "",
      "role_name": "Hypervisor",
      "cinder": "n",
      "glance": "n",
      "designate": "n"
    },
    {
      "pf9-kube": "",
      "nova": "y",
      "node_type": "",
      "role_name": "Hypervisor with Glance",
      "cinder": "n",
      "glance": "y",
      "designate": "n"
    },
    {
      "pf9-kube": "",
      "nova": "y",
      "node_type": "",
      "role_name": "Hypervisor with Cinder",
      "cinder": "y",
      "glance": "n",
      "designate": "n"
    },
    {
      "pf9-kube": "",
      "nova": "y",
      "node_type": "",
      "role_name": "Hypervisor with Designate",
      "cinder": "n",
      "glance": "n",
      "designate": "y"
    },
    {
      "pf9-kube": "y",
      "nova": "",
      "node_type": "master",
      "role_name": "Kubernetes Master",
      "cinder": "",
      "glance": "",
      "designate": ""
    },
    {
      "pf9-kube": "y",
      "nova": "",
      "node_type": "worker",
      "role_name": "Kubernetes Worker",
      "cinder": "",
      "glance": "",
      "designate": ""
    }
  ],
  "auth-profiles": [
    {
      "auth_type": "sshkey",
      "auth_name": "CentOS SSH Access (Key-based)",
      "auth_password": "",
      "auth_username": "centos",
      "auth_ssh_key": "<ssh-keypath>"
    },
    {
      "auth_type": "sshkey",
      "auth_name": "Ubuntu SSH Access (Key-based)",
      "auth_password": "",
      "auth_username": "ubuntu",
      "auth_ssh_key": "<ssh-keypath>"
    }
  ]
}
