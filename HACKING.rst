Patrole Style Commandments
==========================

- Step 1: Read the OpenStack Style Commandments: `<https://docs.openstack.org/developer/hacking/>`__
- Step 2: Review Tempest's Style Commandments: `<https://docs.openstack.org/developer/tempest/HACKING.html>`__
- Step 3: Read on

Patrole Specific Commandments
------------------------------

Patrole borrows the following commandments from Tempest; refer to
`Tempest's Commandments <https://docs.openstack.org/developer/tempest/HACKING.html>`__
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
         an RBAC test (the check fails if the decorator is not one of the
         two decorators directly above the function declaration)
- [P101] RBAC test filenames must end with "_rbac.py"; for example,
         test_servers_rbac.py, not test_servers.py
- [P102] RBAC test class names must end in 'RbacTest'
- [P103] ``self.client`` must not be used as a client alias; this allows for
         code that is more maintainable and easier to read

Role Switching
--------------

Correct role switching is vital to correct RBAC testing within Patrole. If a
test does not call ``rbac_utils.switch_role`` with ``toggle_rbac_role=True``
within the RBAC test, then the test is *not* a valid RBAC test: The API
endpoint under test will be performed with admin credentials, which is always
wrong unless ``CONF.rbac_test_role`` is admin.

.. note::

    Switching back to the admin role for setup and clean up is automatically
    performed. Toggling ``switch_role`` with ``toggle_rbac_role=False`` within
    the context of a test should *never* be performed and doing so will likely
    result in an error being thrown.
..

Patrole does not have a hacking check for role switching, but does use a
built-in mechanism for verifying that role switching is being correctly
executed across tests. If a test does not call ``switch_role`` with
``toggle_rbac_role=True``, then an ``RbacResourceSetupFailed`` exception
will be raised.
