{
  "actions": [
      {
          "operation": "discover-region",
          "region-name": "https://cs-integration-k8s01.platform9.horse"
      },
      {
          "operation": "onboard-region",
          "region-name": "https://cs-integration-k8s01.platform9.horse",
          "cluster-name": "ci-cluster01",
          "masters": "all",
          "workers": "all"
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
      "ip": "",
      "public_ip": "",
      "fk_host_profile": "",
      "node_type": "master",
      "cluster_name": "ci-cluster01",
      "pf9-kube": "y",
      "nova": "n",
      "glance": "n",
      "cinder": "n",
      "designate": "n"
    }
  ]
}
