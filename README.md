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

# MVP-0 (For Monday, Jan 20):
* [done] Remove defaults for username
* [done] Set default for tenant: service
* [done] Change Region Interview text: "Username for Remote Host Access'
* [done] Select Inventory (to run PF9-Express against) [all]
* [done] Auto-start pf9-express/express-cli after 15 seconds
* [blocked-on-tom] Add top-level menu: Express CLI

# For MVP-1 (Feb 3 - Internal Beta)
* Obfuscate (base64 encode) passwords in data model
* Add SSH-based discovery:
- IP interfaces
- Metadata for bond configuration
* Implement Tests
* Travis CI

# For MVP-2 (Feb 24 - External Beta)
* Host Profiles (select in host interview)
* PyPI

# GA | Mar 30:
* Encrypted passwords in data model
* Data Model convergence (Wizard & CLI)
