Ansible role for setup authentication between elasticsearch and logstash
=========

Authentication ELK Stack role. This role include in default terraform scenario for auto-deploy new server.

-------

For manual installation this role:

```ansible-galaxy install tenantcloud.ansible_role_auth_elk```

Add this role name to playbook and run:

```cd /tmp/.ansible/ && ansible-playbook playbook-name.yml```

-------

Variable included in this role:

{{ ea_dir }} - name elastalert directory

-------

Sample playbook-name.yml

- hosts: localhost
  vars:
    ea_dir: elastalert
  become: yes
  roles:
    - ansible-role-auth-elk

