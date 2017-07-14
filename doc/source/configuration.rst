.. _patrole-configuration:

Patrole Configuration Guide
===========================

Patrole can be customized by updating Tempest's ``tempest.conf`` configuration
file. All Patrole-specific configuration options should be included under
the ``rbac`` group.

RBAC Test Role
--------------

The RBAC test role governs which role is used when running Patrole tests. For
example, setting ``rbac_test_role`` to "admin" will execute all RBAC tests
using admin credentials. Changing the ``rbac_test_role`` value will `override`
Tempest's primary credentials to use that role.

This implies that, if ``rbac_test_role`` is "admin", regardless of the Tempest
credentials used by a client, the client will be calling APIs using the admin
role. That is, ``self.os_primary.servers_client`` will run as though it were
``self.os_admin.servers_client``.

Similarly, setting ``rbac_test_role`` to a non-admin role results in Tempest's
primary credentials being overriden by the role specified by
``rbac_test_role``.

.. note::

    Only the role of the primary Tempest credentials ("os_primary") is
    modified. The ``user_id`` and ``project_id`` remain unchanged.

Enable RBAC
-----------

Given the value of ``enable_rbac``, enables or disables Patrole tests. If
``enable_rbac`` is ``False``, then Patrole tests are skipped.

Strict Policy Check
-------------------

Currently, many services define their "default" rule to be "anyone allowed".
If a policy action is not explicitly defined in a policy file, then
``oslo.policy`` will fall back to the "default" rule. This implies that if
there's a typo in a policy action specified in a Patrole test, ``oslo.policy``
can report that the ``rbac_test_role`` will be able to perform the
non-existent policy action. For a testing framework, this is undesirable
behavior.

Hence, ``strict_policy_check``, if ``True``, will throw an error in the event
that a non-existent or bogus policy action is passed to a Patrole test. If
``False``, however, a ``self.skipException`` will be raised.

Custom Policy Files
-------------------

Patrole supports testing custom policy file definitions, along with default
policy definitions. Default policy definitions are used if custom file
definitions are not specified. If both are specified, the custom policy
definition takes precedence (that is, replaces the default definition,
as this is the default behavior in OpenStack).

The ``custom_policy_files`` option allows a user to specify a comma-separated
list of custom policy file locations that are on the same host as Patrole.
Each policy file must include the name of the service that is being tested:
for example, if "compute" tests are executed, then Patrole will use the first
policy file contained in ``custom_policy_files`` that contains the "nova"
keyword.

.. note::

    Patrole currently does not support policy files located on a host different
    than the one on which it is running.
..
