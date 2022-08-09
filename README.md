Security Module Builder
=======================

### Overview:

The `security_rm_builder` is an Ansible Collection that helps developers scaffold and output Ansible Resource Modules (RM) based out of OPENAPI based swagger JSON file, using HTTPAPI connection plugin for the configuration.

**Capabilities:**

- Use a pre-defined OPENAPI based swagger JSON file or other JSON file to scaffold a resource module in an Ansible Collection.
- Generates working resource module file `<vendor>_<resource>.py` and relevant action logic file both `action/<vendor>_<resource>.py`.

**Requirements:**
- Python3
- Ansible

### Usage

```
pip install ansible-base
ansible-galaxy collection install git+https://github.com/ansible-security/security_rm_builder.git
```

```yaml
run.yml
---
- hosts: localhost
  gather_facts: yes
  roles:
    - ansible_security.security_rm_builder.run
```

#### Builing a new module/collection:
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

**Input Parameters:**

- *rm_swagger_json*: Swagger JSON/JSON file where OEMs API with all of its REST operations are defined.
- *rm_dest*: Destination folder where the user wants the output of the scaffolding tool to be stored.
- *api_object_path*: API for which resource module needs to be generated by the tool.
- *module_name*: Ansible module name against the API.
- *resource*: API resource.
- *collection_org*: Ansible collection org name.
- *collection_name*: Ansible collection name.
- *unique_key*: Unique key for API.


### Examples:

**Collection directory layout:**

```
|
├── plugins
│   ├── action
│   │   └── <collection_name_api>.py
│   └── modules
│       └── <collection_name_api>.py
└── tests
```

### Developer Notes:

The tests rely on a collection generated by the cli_rm_builder.
After changes to the builder, this test collection should be regenerated and the tests modified and run as needed.
To generate the collection after changes:

```
tmp
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

run.yml:
```
- hosts: localhost
  gather_facts: yes
  vars:
    rm_swagger_json: /swagger_tm.json
    rm_dest: /tmp/trendmicro/deepsec
    api_object_path: /intrusionpreventionrules
    module_name: 'deepsec_intrusion_prevention_rules'
    module_version: 1.2.0
    resource: intrusion_prevention_rules
    collection_org: trendmicro
    collection_name: deepsec
    unique_key: ""
    author: "Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
  roles:
    - ansible_security.security_rm_builder.run
```

or, directly pass the args as:
```
ansible-playbook -e rm_swagger_json=/swagger_tm.json \
                 -e rm_dest=/tmp/trendmicro/deepsec \
                 -e api_object_path=/intrusionpreventionrules \
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

run.yml:
```
- hosts: localhost
  gather_facts: yes
  vars:
    rm_swagger_json: /FortiOS_7.0.3_Configuration_API_firewall.json
    rm_dest: /tmp/fortinet/fortios
    api_object_path: /firewall/policy
    module_name: fortios_firewall_policy
    module_version: 1.2.0
    resource: firewall_policy
    collection_org: fortinet
    collection_name: fortios
    unique_key: policyid
    author: "Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
  roles:
    - ansible_security.security_rm_builder.run
```

or, directly pass the args as:
```
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

run.yml:
```
- hosts: localhost
  gather_facts: yes
  vars:
    rm_swagger_json: /checkpoint_api.json
    rm_dest: /tmp/checkpoint/mgmt
    api_object_path: add-access-rule
    module_name: cp_mgmt_add_access_rule
    module_version: 1.2.0
    resource: access_rule
    collection_org: checkpoint
    collection_name: mgmt
    unique_key: ""
    author: "Ansible Security Automation Team (@justjais) <https://github.com/ansible-security>"
  roles:
    - ansible_security.security_rm_builder.run
```

or, directly pass the args as:
```
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
