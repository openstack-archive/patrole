Patrole Test Writing Overview
=============================

Introduction
------------

Patrole tests are broken up into 3 stages:

#. :ref:`rbac-test-setup`
#. :ref:`rbac-test-execution`
#. :ref:`rbac-test-cleanup`

See the :ref:`framework overview documentation <framework-overview>` for a
high-level explanation of the entire testing work flow and framework
implementation. The guide that follows is concerned with helping developers
know how to write Patrole tests.

.. _role-overriding:

Role Overriding
---------------

Role overriding is the way Patrole is able to create resources and delete
resources -- including those that require admin credentials -- while still
being able to exercise the same set of Tempest credentials to perform the API
action that authorizes the policy under test, by manipulating the role of
the Tempest credentials.

Patrole implicitly splits up each test into 3 stages: set up, test execution,
and teardown.

The role workflow is as follows:

#. Setup: Admin role is used automatically. The primary credentials are
   overridden with the admin role.
#. Test execution: ``[patrole] rbac_test_role`` is used manually via the
   call to ``with rbac_utils.override_role(self)``. Everything that
   is executed within this contextmanager uses the primary
   credentials overridden with the ``[patrole] rbac_test_role``.
#. Teardown: Admin role is used automatically. The primary credentials have
   been overridden with the admin role.

.. _rbac-test-setup:

Test Setup
----------

Automatic role override in background.

Resources can be set up inside the ``resource_setup`` class method that Tempest
provides. These resources are typically reserved for "expensive" resources
in terms of memory or storage requirements, like volumes and VMs. These
resources are **always** created via the admin role; Patrole automatically
handles this.

Like Tempest, however, Patrole must also create resources inside tests
themselves. At the beginning of each test, the primary credentials have already
been overridden with the admin role. One can create whatever test-level
resources one needs, without having to worry about permissions.

.. _rbac-test-execution:

Test Execution
--------------

Manual role override required.

"Test execution" here means calling the API endpoint that enforces the policy
action expected by the ``rbac_rule_validation`` decorator. Test execution
should be performed *only after* calling
``with rbac_utils.override_role(self)``.

Immediately after that call, the API endpoint that enforces the policy should
be called.

Examples
^^^^^^^^

Always use the contextmanager before calling the API that enforces the
expected policy action.

Example::

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-aggregates:show"])
    def test_show_aggregate_rbac(self):
        # Do test setup before the ``override_role`` call.
        aggregate_id = self._create_aggregate()
        # Call the ``override_role`` method so that the primary credentials
        # have the test role needed for test execution.
        with self.rbac_utils.override_role(self):
            self.aggregates_client.show_aggregate(aggregate_id)

When using a waiter, do the wait outside the contextmanager. "Waiting" always
entails executing a ``GET`` request to the server, until the state of the
returned resource matches a desired state. These ``GET`` requests enforce
a different policy than the one expected. This is undesirable because
Patrole should only test policies in isolation from one another.

Otherwise, the test result will be tainted, because instead of only the
expected policy getting enforced with the ``os_primary`` role, at least
two policies get enforced.

Example using waiter::

    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-admin-password"])
    def test_change_server_password(self):
        original_password = self.servers_client.show_password(
            self.server['id'])
        self.addCleanup(self.servers_client.change_password, self.server['id'],
                        adminPass=original_password)

        with self.rbac_utils.override_role(self):
            self.servers_client.change_password(
                self.server['id'], adminPass=data_utils.rand_password())
        # Call the waiter outside the ``override_role`` contextmanager, so that
        # it is executed with admin role.
        waiters.wait_for_server_status(
            self.servers_client, self.server['id'], 'ACTIVE')

Below is an example of a method that enforces multiple policies getting
called inside the contextmanager. The ``_complex_setup_method`` below
performs the correct API that enforces the expected policy -- in this
case ``self.resources_client.create_resource`` -- but then proceeds to
use a waiter.

Incorrect::

    def _complex_setup_method(self):
        resource = self.resources_client.create_resource(
            **kwargs)['resource']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self._delete_resource, resource)
        waiters.wait_for_resource_status(
            self.resources_client, resource['id'], 'available')
        return resource

    @rbac_rule_validation.action(
        service="example-service",
        rules=["example-rule"])
    def test_change_server_password(self):
        # Never call a helper function inside the contextmanager that calls a
        # bunch of APIs. Only call the API that enforces the policy action
        # contained in the decorator above.
        with self.rbac_utils.override_role(self):
            self._complex_setup_method()

To fix this test, see the "Example using waiter" section above. It is
recommended to re-implement the logic in a helper method inside a test such
that only the relevant API is called inside the contextmanager, with
everything extraneous outside.

.. _rbac-test-cleanup:

Test Cleanup
------------

Automatic role override in background.

After the test -- no matter whether it ended successfully or in failure --
the credentials are overridden with the admin role by the Patrole framework,
*before* ``tearDown`` or ``tearDownClass`` are called. This means that
resources are always cleaned up using the admin role.
