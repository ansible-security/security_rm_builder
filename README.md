Security Module Builder
=======================

### Overview

The `security_rm_builder` is an Ansible Collection that helps developers scaffold and output Ansible Resource Modules (RM) based out of OPENAPI based swagger JSON file, using HTTPAPI connection plugin for the configuration.

**Capabilities**

- Use a pre-defined OPENAPI based swagger JSON file or other JSON file to scaffold a resource module in an Ansible Collection.
- Generates working resource module file `<vendor>_<resource>.py` and relevant action logic file both `action/<vendor>_<resource>.py`.

#### Builing a new module/collection
```
ansible-playbook -e rm_swagger_json=<vendor swagger json file> \
                 -e rm_dest=<destination folder where RM will be generated> \
                 -e api_object_path=<vendor API for generating RM> \
                 -e module_name=<Resource Module name> \
		             -e module_version=<Resource Module version> \
                 -e resource=<resource> \
                 -e collection_org=<vendor collection org> \
                 -e collection_name=<vendor collection name> \
                 -e unique_key=<API primary key> \
                 run.yml
```

### Examples

### run.yml:

```
---
- hosts: localhost
  gather_facts: yes
  roles:
    - ansible_security.security_rm_builder.run
```

**Collection directory layout**

```
|
├── plugins
│   ├── action
│   │   └── <collection_name_api.py>
│   └── modules
│       ├── <collection_name_api.py>.py
└── tests
```

### Developer Notes

The tests rely on a collection generated by the cli_rm_builder.
After changes to the builder, this test collection should be regenerated and the tests modified and run as needed.
To generate the collection after changes:

```
tests
└── rmb_tests
    └── collections
        └── ansible_collections
            └── trendmicro
                └── deepsec
                    ├── plugins
                    │   ├── action
                    │   │   └── deepsec_intrusion_prevention_rules.py
                    │   └── modules
                    │       └── deepsec_intrusion_prevention_rules.py
                    └── tests
```

### 1. Trendmicro
```
rm -rf tests/rmb_tests/collections/ansible_collections/trendmicro
ansible-playbook -e rm_swagger_json=/swagger_tm.json \
                 -e rm_dest=/tmp/trendmicro/deepsec \
                 -e api_object_path=/intrusionpreventionrules/post \
                 -e module_name='deepsec_intrusion_prevention_rules' \
                 -e module_version=1.2.0 \
                 -e resource=intrusion_prevention_rules \
                 -e collection_org=trendmicro \
                 -e collection_name=deepsec \
                 -e unique_key="" \
                 -e author="Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
                 run.yaml
```

### 2. Fortinet
```
rm -rf tests/rmb_tests/collections/ansible_collections/fortinet/fortios
ansible-playbook -e rm_swagger_json=/FortiOS_7.0.3_Configuration_API_firewall.json \
                 -e rm_dest=/tmp/fortinet/fortios \
                 -e api_object_path=/firewall/policy \
                 -e module_name='fortios_firewall_policy' \
                 -e module_version=1.2.0 \
                 -e resource=firewall_policy \
                 -e collection_org=fortinet \
                 -e collection_name=fortios \
                 -e unique_key=policyid \
                 -e author="Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
		run.yaml -vvvv
```

### 2. CheckPoint
```
rm -rf tests/rmb_tests/collections/ansible_collections/checkpoint/mgmt
ansible-playbook -e rm_swagger_json=/checkpoint_api.json \
                 -e rm_dest=/tmp/checkpoint/mgmt \
                 -e api_object_path="add-access-rule" \
                 -e module_name='cp_mgmt_add_access_rule' \
                 -e module_version=1.2.0 \
                 -e resource=access_rule \
                 -e collection_org=checkpoint \
                 -e collection_name=mgmt \
                 -e unique_key="" \
                 -e author="Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
		run.yaml -vvvv
```

License
-------

BSD

Author Information
------------------

Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>.
