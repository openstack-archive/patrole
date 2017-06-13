========================
Team and repository tags
========================

.. image:: http://governance.openstack.org/badges/patrole.svg
    :target: http://governance.openstack.org/reference/tags/index.html

..

=========================================
Patrole - RBAC Integration Tempest Plugin
=========================================

Patrole is a tool for verifying that Role-Based Access Control is being
correctly enforced.

Patrole allows users to run API tests using specified RBAC roles. This allows
deployments to verify that only intended roles have access to those APIs.
This is critical to ensure security, especially in large deployments with
custom roles.

* Free software: Apache license
* Documentation: https://docs.openstack.org/developer/patrole
* Source: https://git.openstack.org/cgit/openstack/patrole
* Bugs: https://bugs.launchpad.net/patrole

Features
========
Patrole offers RBAC testing for various OpenStack RBAC policies. It includes
a decorator that wraps around tests which verifies that when the test calls the
corresponding API endpoint, access is only granted for correct roles.

Currently, Patrole supports policies contained in code and in policy.json files.
If both exist, the policy actions in the policy.json are prioritized.

Stable Interface
----------------
Patrole offers a stable interface that is guaranteed to be backwards compatible and
can be directly consumed by other projects. Currently, rbac_exceptions.py and
rbac_policy_parser.py are guaranteed to be stable.

Release Versioning
------------------
`Patrole Release Notes <https://docs.openstack.org/releasenotes/patrole/>`_ show
what changes have been released.

.. _test-flows:

Test Flows
----------
There are several possible test flows.

If the ``rbac_test_role`` is allowed to access the endpoint:

* The test passes if no 403 ``Forbidden`` or ``RbacActionFailed`` exception is raised.

If the ``rbac_test_role`` is not allowed to access the endpoint:

* If the endpoint returns a 403 `Forbidden` exception the test will pass.
* If the endpoint returns successfully, then the test will fail with an
  ``RbacOverPermission`` exception.
* If the endpoint returns something other than a 403 ``Forbidden`` to indicate
  that the role is not allowed, the test will raise an ``RbacActionFailed`` exception.

.. note::

    Certain services like Neutron *intentionally* raise a 404 instead of a 403
    for security concerns. Patrole accomodates this behavior by anticipating
    a 404 instead of a 403, using the ``expected_exception`` argument. For more
    information about Neutron's policy enforcement, see:
    `<https://docs.openstack.org/developer/neutron/devref/policy.html#request-authorization>`__.

How It Works
============
Patrole leverages oslo_policy (OpenStack's policy enforcement engine) to
determine whether a given role is allowed to perform a policy action given a
specific rule and OpenStack service. This is done before test execution inside
the ``rbac_rule_validation.action`` decorator. Then, inside the test, the API
that does policy enforcement for the same rule is called. The outcome is
compared against the result from oslo_policy and a pass or fail is determined
as outlined above: `Test Flows`_.

.. note::

    Currently, Patrole does not support checking multiple rules against a single
    API call. Even though some APIs enforce multiple rules (some indirectly),
    it is increasingly difficult to maintain the tests if multiple policy
    actions are expected to be called.

Test Execution Workflow
-----------------------
The workflow is as follows:

#. Each test uses the ``rbac_rule_validation.action`` decorator, like below: ::

    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:servers:stop")
    @decorators.idempotent_id('ab4a17d2-166f-4a6d-9944-f17baa576cf2')
    def test_stop_server(self):
        # Set the primary credential's role to "rbac_test_role".
        self.rbac_utils.switch_role(self, toggle_rbac_role=True)
        # Call the API that enforces the policy action specified by "rule".
        self._test_stop_server()

   The ``service`` attribute accepts an OpenStack service and the ``rule`` attribute
   accepts a valid OpenStack policy action, like "os_compute_api:servers:stop".

#. The ``rbac_rule_validation.action`` decorator passes these attributes,
   along with user_id and project_id information derived from the primary
   Tempest credential (``self.os.credentials.user_id`` and ``self.os.credentials.project_id``),
   to the ``rbac_policy_parser``.

#. The logic in ``rbac_policy_parser`` then passes all this information along
   and the role in ``CONF.rbac.rbac_test_role`` to oslo_policy to determine whether
   the ``rbac_test_role`` is authorized to perform the policy action for the given
   service.

#. After all of the logic above has executed inside the rbac decorator, the
   test is executed. The test then sets up test-level resources, if necessary,
   with **admin** credentials implicitly. This is accomplished through
   ``rbac_utils.switch_role(toggle_rbac_role=False)``, which is done as part of
   client setup (inside the call to ``rbac_utils.RbacUtils``): ::

    @classmethod
    def setup_clients(cls):
        super(BaseV2ComputeRbacTest, cls).setup_clients()
        cls.auth_provider = cls.os_primary.auth_provider
        cls.rbac_utils = rbac_utils.RbacUtils(cls)
        ...

   This code has *already* executed when the test class is instantiated, because
   it is located in the base rbac test class. Whenever ``cls.rbac_utils.switch_role``
   is called, one of two behaviors are possible:

    #. The primary credential's role is changed to admin if ``toggle_rbac_role=False``
    #. The primary credential's role is changed to ``rbac_test_role`` if
       ``toggle_rbac_role=True``

   Thus, at the *beginning* of every test and during ``resource_setup`` and
   ``resource_cleanup``, the primary credential has the admin role.

#. After preliminary test-level setup is performed, like creating a server, a
   second call to ``self.rbac_utils.switch_role`` is done: ::

    self.rbac_utils.switch_role(cls, toggle_rbac_role=True)

   Now the primary credential has the role specified by ``rbac_test_role``.

#. The API endpoint in which policy enforcement of "os_compute_api:servers:stop"
   is performed can now be called.

   .. note:

        To determine whether a policy action is enforced, refer to the relevant
        controller code to make sure that the policy action is indeed enforced.

#. Now that a call is made to "stop_server" with the primary credentials having
   the role specified by ``rbac_test_role``, either the nova contoller will allow
   or disallow the action to be performed. Since the "stop_server" policy action in
   nova is defined as "base.RULE_ADMIN_OR_OWNER", the API will most likely
   return a successful status code. For more information about this policy action,
   see `<https://github.com/openstack/nova/blob/master/nova/policies/servers.py>`__.

#. As mentioned above, the result from the API call and the result from oslo_policy
   are compared for consistency.

#. Finally, after the test has executed, but before ``tearDown`` or ``resource_cleanup``
   is called, ``self.rbac_utils.switch_role(cls, toggle_rbac_role=False)`` is
   called, so that the primary credential yet again has admin permissions for
   test clean up. This call is always performed in the "finally" block inside
   the ``rbac_rule_validation`` decorator.

.. warning::

    Failure to call ``self.rbac_utils.switch_role(cls, toggle_rbac_role=True)``
    inside a test with the ``rbac_rule_validation`` decorator applied results
    in a ``RbacResourceSetupFailed`` being raised, causing the test to fail.
