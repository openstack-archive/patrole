..

========
Usage
========

Running Patrole Tests in Tempest
================================

If Patrole is installed correctly, then the API tests can be executed
from inside the tempest root directory as follows: ::

    tox -eall-plugin -- patrole_tempest_plugin.tests.api

To execute patrole tests for a specific module, run: ::

    tox -eall-plugin -- patrole_tempest_plugin.tests.api.compute

To change the role that the patrole tests are being run as, edit
``rbac_test_role`` in the ``rbac`` section of tempest.conf: ::

    [rbac]
    rbac_test_role = Member
    ...

.. note::

    The ``rbac_test_role`` is service-specific. Member, for example,
    is an arbitrary role, but by convention is used to designate the default
    non-admin role in the system. Most patrole tests should be run with
    **admin** and **Member** roles. However, some services, like Heat, take
    advantage of a role called **heat_stack_user**, as it appears frequently
    in Heat's policy.json.

For more information about the Member role,
please see: `<https://ask.openstack.org/en/question/4759/member-vs-_member_/>`__.
