============
Installation
============

Installation Information
########################

At the command line::

    $ pip install patrole

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv patrole
    $ pip install patrole

Configuration Information
#########################

tempest.conf
++++++++++++

To run the RBAC tempest api test you have to make the following changes to
the tempest.conf file.

#. [auth] section updates ::

       # Set tempest role to admin so all APIs are accessible
       tempest_roles = admin

       # Allows test cases to create/destroy tenants and users. This
       # option enables isolated test cases and better parallel
       # execution, but also requires that OpenStack Identity API
       # admin credentials are known. (boolean value)
       allow_tenant_isolation = True

       # Allows test cases to create/destroy projects and users. This option
       # requires that OpenStack Identity API admin credentials are known. If
       # false, isolated test cases and parallel execution, can still be
       # achieved configuring a list of test accounts (boolean value)
       use_dynamic_credentials = False

#. [rbac] section updates ::

       # The role that you want the RBAC tests to use for RBAC testing
       rbac_role=_member_
       # Tell standard RBAC test cases to run other wise it they are skipped.
       rbac_flag=true
