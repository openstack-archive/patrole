========================
Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/patrole.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

Patrole - RBAC Integration Tempest Plugin
=========================================

Patrole is a security validation tool for verifying that Role-Based Access
Control is correctly configured and enforced in a system. It runs
`Tempest`_-based API tests using specified RBAC roles, thus allowing
deployments to verify that only intended roles have access to those APIs.

Patrole currently offers testing for the following OpenStack services: Nova,
Neutron, Glance, Cinder and Keystone.

Patrole is currently undergoing heavy development. As more projects move
toward policy in code, Patrole will align its testing with the appropriate
documentation.

.. _Tempest: https://docs.openstack.org/tempest/latest/

Design Principles
-----------------

Patrole borrows some design principles from Tempest, but not all, as its
testing scope is confined to policies.

* *Stability*. Patrole uses OpenStack public interfaces. Tests in Patrole
  should only touch public OpenStack APIs.
* *Atomicity*. Patrole tests should be atomic: they should test policies in
  isolation. Unlike Tempest, a Patrole test strives to only call a single
  endpoint at a time.
* *Holistic coverage*. Patrole strives for complete coverage of the OpenStack
  API. Additionally, Patrole strives to test the API-to-policy mapping
  contained in each project's policy in code documentation.
* *Self-contained*. Patrole should attempt to clean up after itself; whenever
  possible we should tear down resources when done.

  .. note::

      Patrole modifies roles dynamically in the background, which affects
      pre-provisioned credentials. Work is currently underway to clean up
      modifications made to pre-provisioned credentials.

* *Self-tested*. Patrole should be self-tested.

Features
--------
* Validation of default policy definitions located in policy.json files.
* Validation of in-code policy definitions.
* Validation of custom policy file definitions that override default policy
  definitions.
* Built-in positive and negative testing. Positive and negative testing
  are performed using the same tests and role-switching.
* Valdation of custom roles as well as default OpenStack roles.

.. note::

    Patrole does not yet support policy.yaml files, the new file format for
    policy files in OpenStack.

How It Works
------------
Patrole leverages ``oslo.policy`` (OpenStack's policy enforcement engine) to
determine whether a given role is allowed to perform a policy action, given a
specific role and OpenStack service. The output from ``oslo.policy`` (the
expected result) and the actual result from test execution are compared to
each other: if both results match, then the test passes; else it fails.

* Documentation: https://docs.openstack.org/patrole/latest/
* Bugs: https://bugs.launchpad.net/patrole

Quickstart
----------
Tempest is a prerequisite for running Patrole. If you do not have Tempest
installed, please reference the official Tempest documentation for guidance.

Assuming Tempest is installed, the simplest way to configure Patrole is:

1. Open up the ``tempest.conf`` configuration file and include the following
settings:

.. code-block:: ini

    [rbac]
    enable_rbac = True
    rbac_test_role = admin

These settings tell Patrole to run RBAC tests using the "admin" role (which
is the default admin role in OpenStack) to verify the default policy
definitions used by OpenStack services. Specifying a different role
for ``rbac_test_role`` will run Patrole tests against that role. For additional
information about Patrole's configuration settings, please refer to
:ref:`patrole-configuration` and :ref:`patrole-sampleconf` for a sample
configuration file.

2. You are now ready to run Patrole. To do so, you can use any testr-based test
runner::

    $ testr run patrole_tempest_plugin.tests.api

or::

    $ ostestr --regex '(?!.*\[.*\bslow\b.*\])(^patrole_tempest_plugin\.tests\.api)'

It is also possible to run Patrole using tox::

    tox -eall-plugin -- patrole_tempest_plugin.tests.api

Release Versioning
------------------
`Patrole Release Notes <https://docs.openstack.org/releasenotes/patrole/>`_
shows which changes have been released for each version.

Patrole's release versioning follows Tempest's conventions. Like Tempest,
Patrole is branchless and uses versioning instead.
