.. _rbac-utils:

The RBAC Utils Module
=====================

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

Patrole, therefore, implicitly splits up each test into 3 stages: set up,
test execution, and teardown.

The role workflow is as follows:

#. Setup: Admin role is used automatically. The primary credentials are
   overridden with the admin role.
#. Test execution: ``[patrole] rbac_test_role`` is used manually via a call
   to ``rbac_utils.switch_role(self, toggle_rbac_role=True)``. Everything that
   is executed after this call, until the end of the test, uses the primary
   credentials overridden with the ``rbac_test_role``.
#. Teardown: Admin role is used automatically. The primary credentials have
   been overridden with the admin role.

.. _Tempest credentials: https://docs.openstack.org/tempest/latest/library/credential_providers.html
.. _dynamic credentials: https://docs.openstack.org/tempest/latest/configuration.html#dynamic-credentials

Test Setup
----------

Automatic role switch in background.

Resources can be set up inside the ``resource_setup`` class method that Tempest
provides. These resources are typically reserved for "expensive" resources
in terms of memory or storage requirements, like volumes and VMs. These
resources are **always** created via the admin role; Patrole automatically
handles this.

Like Tempest, however, Patrole must also create resources inside tests
themselves. At the beginning of each test, the primary credentials have already
been overridden with the admin role. One can create whatever test-level
resources one needs, without having to worry about permissions.

Test Execution
--------------

Manual role switch required.

"Test execution" here means calling the API endpoint that enforces the policy
action expected by the ``rbac_rule_validation`` decorator. Test execution
should be performed *only after* calling
``rbac_utils.switch_role(self, toggle_rbac_role=True)``.

Immediately after that call, the API endpoint that enforces the policy should
be called.

Example::

    # Always apply the RBAC decorator to the test.
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-aggregates:show")
    def test_show_aggregate_rbac(self):
        # Do test setup before the switch_role call.
        aggregate_id = self._create_aggregate()
        # Call the switch_role method so that the primary credentials have
        # the test role needed for test execution.
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Call the endpoint that enforces the expected policy action, described
        # by the "rule" kwarg in the decorator above.
        self.aggregates_client.show_aggregate(aggregate_id)

Test Cleanup
------------

Automatic role switch in background.

After the test -- no matter whether it ended successfully or in failure --
the credentials are overridden with the admin role by the Patrole framework,
*before* ``tearDown`` or ``tearDownClass`` are called. This means that
resources are always cleaned up using the admin role.

Implementation
--------------

.. automodule:: patrole_tempest_plugin.rbac_utils
   :members:
   :private-members:
