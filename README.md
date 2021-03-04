
![Lint Ansible Roles](https://github.com/tenantcloud/ansible-role-auth-elk/workflows/Lint%20Ansible%20Roles/badge.svg)

tenantcloud.auth_elk
=========

Ansible role for setup authentication between elasticsearch and logstash. This role include in default terraform scenario for auto-deploy new server.

Requirements
------------

ELK Stack, Elastalert, ReadOnlyRest

Role Variables
--------------

ea_dir: elastalert
Name elastalert directory

Dependencies
------------

  - geerlingguy.java
  - tenantcloud.elasticsearch
  - tenantcloud.kibana
  - tenantcloud.logstash
  - tenantcloud.ansible_role_elastalert

Example Playbook
----------------

```yaml
- hosts: localhost
  vars:
    ea_dir: elastalert
    elk_url: 194.44.100.100
  become: yes
  roles:
    - tenantcloud.auth_elk
```

License
-------

BSD

Author Information
------------------

TenantCloud DevOps Team
