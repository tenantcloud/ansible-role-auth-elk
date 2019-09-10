tenantcloud.ansible_role_auth_elk
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
  - geerlingguy.elasticsearch
  - geerlingguy.kibana
  - geerlingguy.logstash
  - tenantcloud.ansible_role_elastalert

Example Playbook
----------------

  - hosts: localhost
    vars:
      ea_dir: elastalert
    become: yes
    roles:
      - ansible-role-auth-elk

License
-------

BSD

Author Information
------------------

TenantCloud DevOps Team
