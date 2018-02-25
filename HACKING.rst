Patrole Style Commandments
==========================

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
..

- [T102] Cannot import OpenStack python clients in patrole_tempest_plugin/tests/api
- [T105] Tests cannot use setUpClass/tearDownClass
- [T106] vim configuration should not be kept in source files.
- [T107] Check that a service tag isn't in the module path
- [T108] Check no hyphen at the end of rand_name() argument
- [T109] Cannot use testtools.skip decorator; instead use
         decorators.skip_because from tempest.lib
- [T113] Check that tests use data_utils.rand_uuid() instead of uuid.uuid4()
- [N322] Method's default argument shouldn't be mutable

The following are Patrole's specific Commandments:

- [P100] The ``rbac_rule_validation.action`` decorator must be applied to
         an RBAC test
- [P101] RBAC test filenames must end with "_rbac.py"; for example,
         test_servers_rbac.py, not test_servers.py
- [P102] RBAC test class names must end in 'RbacTest'
- [P103] ``self.client`` must not be used as a client alias; this allows for
         code that is more maintainable and easier to read

Role Overriding
---------------

Correct role overriding is vital to correct RBAC testing within Patrole. If a
test does not call ``rbac_utils.override_role`` within the RBAC test, followed
by the API endpoint that enforces the expected policy action, then the test is
**not** a valid Patrole test: The API endpoint under test will be performed
with admin role, which is always wrong unless ``CONF.patrole.rbac_test_role``
is also admin.

.. todo::

    Patrole does not have a hacking check for role overriding, but one may be
    added in the future.
