.. _patrole-sampleconf:

Sample Configuration File
==========================

The following is a sample Patrole configuration for adaptation and use.

.. code-block:: ini

    [rbac]

    # The role that you want the RBAC tests to use for RBAC testing
    # This needs to be edited to run the test as a different role.
    rbac_test_role = Member

    # Enables RBAC Tempest tests if set to True. Otherwise, they are
    # skipped.
    enable_rbac = True

    # If set to True, tests throw a RbacParsingException for policies
    # not found in the policy file. Otherwise, they throw a skipException.
    strict_policy_check = False

    # List of the paths to search for policy files. Each policy path assumes that
    # the service name is included in the path once. Also assumes Patrole is on the
    # same host as the policy files. The paths should be ordered by precedence,
    # with high-priority paths before low-priority paths. The first path that is
    # found to contain the service's policy file will be used.
    custom_policy_files = /etc/nova/policy.json,/etc/neutron/policy.json

    # This option determines whether Patrole should run against a
    # `custom_requirements_file` which defines RBAC requirements. The
    # purpose of setting this flag to True is to verify that RBAC policy
    # is in accordance to requirements. The idea is that the
    # `custom_requirements_file` perfectly defines what the RBAC requirements
    # are.
    test_custom_requirements = False

    # File path of the yaml file that defines your RBAC requirements. This
    # file must be located on the same host that Patrole runs on. The yaml
    # file should be written as follows:
    custom_requirements_file = patrole/requirements.txt

    # DEPRECATED: The following config options set the location of the service's
    # policy file. For services that have their policy in code (e.g., Nova),
    # this would be the location of a custom policy.json, if one exists.
    cinder_policy_file = /etc/cinder/policy.json
    glance_policy_file = /etc/glance/policy.json
    keystone_policy_file = /etc/keystone/policy.json
    neutron_policy_file = /etc/neutron/policy.json
    nova_policy_file = /etc/nova/policy.json
