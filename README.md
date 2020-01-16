# Platform9 Express Wizard
This script is the public entry point for attaching hosts to Platform9 regions.

# To start the Platform9 Onboarding process, run the following command:
```
bash <(curl -s https://raw.githubusercontent.com/platform9/express-wizard/master/wizard.sh)
```
# Testing Notes:
* To test on Python3 on Centos-7:
```
sudo yum install centos-release-scl
sudo yum install rh-python36
scl enable rh-python36 bash
/opt/rh/rh-python36/root/usr/bin/python
```

# Travis CI:
* implement tests

# To-Do's:
* Add SSH-based discovery:
** ip interfaces
** metadata for bond configuration
* Add top-level menu: Express CLI
* Remove defaults for username
* Set default for tenant: service
* Username for Remote Host Access
* Install Host Agent and Authorize ???
* Select Inventory (to run PF9-Express against) [all]
* Auto-start express-cli cluster attach-node after 10 seconds
* Ideas:
* Host Profiles (select in host interview)
