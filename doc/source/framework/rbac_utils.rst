.. _rbac-utils:

RBAC Utils Module
=================

Overview
--------

Patrole manipulates the ``os_primary`` `Tempest credentials`_, which are the
primary set of Tempest credentials. It is necessary to use the same credentials
across the entire test setup/test execution/test teardown workflow
because otherwise 400-level errors will be thrown by OpenStack services.

This is because many services check the request context's project scope -- and
in very rare cases, user scope. However, each set of Tempest credentials (via
`dynamic credentials`_) is allocated its own distinct project. For example, the
``os_admin`` and ``os_primary`` credentials each have a distinct project,
meaning that it is not always possible for the ``os_primary`` credentials to
access resources created by the ``os_admin`` credentials.

The only foolproof solution is to manipulate the role for the same set of
credentials, rather than using distinct credentials for setup/teardown
and test execution, respectively. This is especially true when considering
custom policy rule definitions, which can be arbitrarily complex.

Implementation
--------------

.. automodule:: patrole_tempest_plugin.rbac_utils
   :members:
   :private-members:
   :special-members:

.. _Tempest credentials: https://docs.openstack.org/tempest/latest/library/credential_providers.html
.. _dynamic credentials: https://docs.openstack.org/tempest/latest/configuration.html#dynamic-credentials

