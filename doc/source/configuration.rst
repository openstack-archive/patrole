.. _patrole-configuration:

Patrole Configuration Guide
===========================

Patrole can be customized by updating Tempest's ``tempest.conf`` configuration
file. All Patrole-specific configuration options should be included under
the ``patrole`` group.

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
primary credentials being overridden by the role specified by
``rbac_test_role``.

.. note::

    Only the role of the primary Tempest credentials ("os_primary") is
    modified. The ``user_id`` and ``project_id`` remain unchanged.

Enable RBAC
-----------

Given the value of ``enable_rbac``, enables or disables Patrole tests. If
``enable_rbac`` is ``False``, then Patrole tests are skipped.

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

Policy Feature Flags
--------------------

Patrole's ``[policy-feature-enabled]`` configuration group includes one option
per supported policy feature flag. These feature flags are introduced when an
OpenStack service introduces a new policy or changes a policy in a
backwards-incompatible way. Since Patrole is branchless, it copes with the
unexpected policy change by making the relevant policy change as well, but
also introduces a new policy feature flag so that the test won't break N-1/N-2
releases where N is the currently supported release.

The default value for the feature flag is enabled for N and disabled for any
releases prior to N in which the feature is not available. This is done by
overriding the default value of the feature flag in DevStack's ``lib/patrole``
installation script. The change is made in Tempest's DevStack script because
Patrole's DevStack plugin is hosted in-repo, which is branch-less (whereas
the former is branched).

After the backwards-incompatible change no longer affects any supported
release, then the corresponding policy feature flag is removed.

For more information on feature flags, reference the relevant
`Tempest documentation`_.

.. _Tempest documentation: https://docs.openstack.org/tempest/latest/HACKING.html#1-new-tests-for-new-features

Sample Configuration File
-------------------------

The following is a sample Patrole configuration for adaptation and use. It is
auto-generated from Patrole when this documentation is built, so
if you are having issues with an option, please compare your version of
Patrole with the version of this documentation.

Note that the Patrole configuration options actually live inside the Tempest
configuration file; at runtime, Tempest populates its own configuration
file with Patrole groups and options, assuming that Patrole is correctly
installed and recognized as a plugin.

The sample configuration can also be viewed in `file form <_static/patrole.conf.sample>`_.

.. literalinclude:: _static/patrole.conf.sample
