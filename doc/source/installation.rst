============
Installation
============

Installation Information
========================

At the command line::

    $ sudo pip install patrole

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv patrole
    $ sudo pip install patrole

Or to install from the source::

    $ navigate to patrole directory
    $ sudo pip install -e .

Configuration Information
=========================

tempest.conf
++++++++++++

To run the RBAC tempest api test, you have to make the following changes to
the tempest.conf file.

#. ``auth`` section updates ::

    # Allows test cases to create/destroy projects and users. This option
    # requires that OpenStack Identity API admin credentials are known. If
    # false, isolated test cases and parallel execution, can still be
    # achieved configuring a list of test accounts (boolean value)
    use_dynamic_credentials = True

#. ``rbac`` section updates ::

    # The role that you want the RBAC tests to use for RBAC testing
    # This needs to be edited to run the test as a different role.
    rbac_test_role = _member_

    # Enables RBAC Tempest tests if set to True. Otherwise, they are
    # skipped.
    enable_rbac = True

    # If set to true, tests throw a RbacParsingException for policies
    # not found in the policy.json. Otherwise, they throw a
    # skipException.
    strict_policy_check = False
