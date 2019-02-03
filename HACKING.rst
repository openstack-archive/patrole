Patrole Coding Guide
====================

- Step 1: Read the OpenStack Style Commandments: `<https://docs.openstack.org/hacking/latest/>`__
- Step 2: Review Tempest's Style Commandments: `<https://docs.openstack.org/tempest/latest/HACKING.html>`__
- Step 3: Read on

Patrole Specific Commandments
------------------------------

Patrole borrows the following commandments from Tempest; refer to
`Tempest's Commandments <https://docs.openstack.org/tempest/latest/HACKING.html>`__
for more information:

.. note::

    The original Tempest Commandments do not include Patrole-specific paths.
    Patrole-specific paths replace the Tempest-specific paths within Patrole's
    hacking checks.

- [T102] Cannot import OpenStack python clients in
  ``patrole_tempest_plugin/tests/api``
- [T105] Tests cannot use setUpClass/tearDownClass
- [T106] vim configuration should not be kept in source files.
- [T107] Check that a service tag isn't in the module path
- [T108] Check no hyphen at the end of rand_name() argument
- [T109] Cannot use testtools.skip decorator; instead use
  ``decorators.skip_because`` from ``tempest.lib``
- [T113] Check that tests use ``data_utils.rand_uuid()`` instead of
  ``uuid.uuid4()``
- [N322] Method's default argument shouldn't be mutable

The following are Patrole's specific Commandments:

- [P100] The ``rbac_rule_validation.action`` decorator must be applied to
  all RBAC tests
- [P101] RBAC test filenames must end with "_rbac.py"; for example,
  test_servers_rbac.py, not test_servers.py
- [P102] RBAC test class names must end in 'RbacTest'
- [P103] ``self.client`` must not be used as a client alias; this allows for
  code that is more maintainable and easier to read
- [P104] RBAC `extension test class`_ names must end in 'ExtRbacTest'

.. _extension test class: https://git.openstack.org/cgit/openstack/patrole/plain/patrole_tempest_plugin/tests/api/network/README.rst

Supported OpenStack Components
------------------------------

Patrole only offers **in-tree** integration testing coverage for the following
components:

* Cinder
* Glance
* Keystone
* Neutron
* Nova

Patrole currently has no stable library, so reliance upon Patrole's framework
for external RBAC testing should be done with caution. Nonetheless, even when
Patrole has a stable library, it will only offer in-tree RBAC testing for
the components listed above.

Role Overriding
---------------

Correct role overriding is vital to correct RBAC testing within Patrole. If a
test does not call ``self.override_role()`` within the RBAC test, followed
by the API endpoint that enforces the expected policy action, then the test is
**not** a valid Patrole test: The API endpoint under test will be performed
with admin role, which is always wrong unless ``CONF.patrole.rbac_test_role``
is also admin.

.. todo::

    Patrole does not have a hacking check for role overriding, but one may be
    added in the future.

Branchless Patrole Considerations
---------------------------------

Like Tempest, Patrole is branchless. This is to better ensure API and RBAC
consistency between releases because API and RBAC behavior should not change
between releases. This means that the stable branches are also gated by the
Patrole master branch, which also means that proposed commits to Patrole must
work against both the master and all the currently supported stable branches
of the projects. As such there are a few special considerations that have to
be accounted for when pushing new changes to Patrole.

1. New Tests for new features
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Patrole, like Tempest, *implicitly* tests new features because new policies
oftentimes accompany new features. The same `Tempest philosophy`_ regarding
feature flags and new features also applies to Patrole.

.. _Tempest philosophy: https://docs.openstack.org/tempest/latest/HACKING.html#new-tests-for-new-features

2. New Tests for new policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When adding tests for new policies that were not in previous releases of the
projects, the new test must be properly skipped with a feature flag. This
involves using the ``testtools.skip(Unless|If)`` decorator above the test
to check if the required policy is enabled. Similarly, a feature flag must
be used whenever an OpenStack service covered by Patrole changes one of its
policies in a backwards-incompatible way. If there isn't a method of selecting
the new policy from the config file then there won't be a mechanism to disable
the test with older stable releases and the new test won't be able to merge.

Introduction of a new feature flag requires specifying a default value for the
corresponding config option that is appropriate in the latest OpenStack
release. Because Patrole is branchless, the feature flag's default value will
need to be overridden to a value that is appropriate in earlier releases in
which the feature isn't available. In DevStack, this can be accomplished by
modifying Patrole's lib installation script for previous branches (because
DevStack is branched).

3. Bug fix on core project needing Patrole changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When trying to land a bug fix which changes a tested API you'll have to use the
following procedure:

    #. Propose change to the project, get a +2 on the change even with the
       test failing Patrole side.
    #. Propose skip to the relevant Patrole test which will only be approved
       after the corresponding change in the project has a +2.
    #. Land project change in master and all open stable branches
       (if required).
    #. Land changed test in Patrole.

Otherwise the bug fix won't be able to land in the project.

4. New Tests for existing features or policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The same `Tempest logic`_ regarding new tests for existing features or
policies also applies to Patrole.

.. _Tempest logic: https://docs.openstack.org/tempest/latest/HACKING.html#new-tests-for-existing-features


Black Box vs. White Box Testing
-------------------------------

Tempest is a `black box testing framework`_, meaning that it is concerned with
testing public API endpoints and doesn't concern itself with testing internal
implementation details. Patrole, as a Tempest plugin, also falls underneath
the category of black box testing. However, even with policy in code
documentation, some degree of white box testing is required in order to
correctly write RBAC tests.

This is because :ref:`policy-in-code` documentation, while useful in many
respects, is usually quite brief and its main purpose is to help operators
understand how to customize policy configuration rather than to help
developers understand complex policy authorization work flows. For example,
policy in code documentation doesn't make deriving
:ref:`multiple policies <multiple-policies>` easy. Such documentation also
doesn't usually mention that a specific parameter needs to be set, or that a
particular microversion must be enabled, or that a particular set of
prerequisite API or policy actions must be executed, in order for the policy
under test to be enforced by the server. This means that test writers must
account for the internal RBAC implementation in API code in order to correctly
understand the complete RBAC work flow within an API.

Besides, as mentioned :ref:`elsewhere <design-principles>` in this
documentation, not all services currently implement policy in code, making
some degree of white box testing a "necessary evil" for writing robust RBAC
tests.

.. _black box testing framework: https://docs.openstack.org/tempest/latest/HACKING.html#negative-tests
