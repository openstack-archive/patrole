========================
Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/patrole.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

Patrole - RBAC Integration Tempest Plugin
=========================================

Patrole is a set of integration tests to be run against a live OpenStack
cluster. It has a battery of tests dedicated to validating the correctness and
integrity of the cloud's RBAC implementation.

More importantly, Patrole is a security validation tool for verifying that
Role-Based Access Control is correctly configured and enforced in an OpenStack
cloud. It runs `Tempest`_-based API tests using specified RBAC roles, thus
allowing deployments to verify that only intended roles have access to those
APIs.

Patrole currently offers testing for the following OpenStack services: Nova,
Neutron, Glance, Cinder and Keystone.

Patrole is currently undergoing heavy development. As more projects move
toward policy in code, Patrole will align its testing with the appropriate
documentation.

* Free software: Apache license
* Documentation: https://docs.openstack.org/patrole/latest
* Source: https://git.openstack.org/cgit/openstack/patrole
* Bugs: https://bugs.launchpad.net/patrole
* Release notes: https://docs.openstack.org/releasenotes/patrole/

.. _design-principles:

Design Principles
-----------------

As a `Tempest plugin`_, Patrole borrows some `design principles`_ from Tempest,
but not all, as its testing scope is confined to policies.

* *Stability*. Patrole uses OpenStack public interfaces. Tests in Patrole
  should only touch public OpenStack APIs.
* *Atomicity*. Patrole tests should be atomic: they should test policies in
  isolation. Unlike Tempest, a Patrole test strives to only call a single
  endpoint at a time. This is because it is important to validate each policy
  is authorized correctly and the best way to do that is to validate each
  policy alone, to avoid test contamination.
* *Complete coverage*. Patrole should validate all policy in code defaults. For
  testing, Patrole uses the API-to-policy mapping contained in each project's
  `policy in code`_ documentation where applicable.

  For example, Nova's policy in code documentation is located in the
  `Nova repository`_ under ``nova/policies``. Likewise, Keystone's policy in
  code documentation is located in the `Keystone repository`_ under
  ``keystone/common/policies``. The other OpenStack services follow the same
  directory layout pattern with respect to policy in code.

  .. note::

    Realistically this is not always possible because some services have
    not yet moved to policy in code.

* *Customizable*. Patrole should be able to validate custom policy overrides to
  ensure that those overrides enhance rather than undermine the cloud's RBAC
  configuration. In addition, Patrole should be able to validate any role.
* *Self-cleaning*. Patrole should attempt to clean up after itself; whenever
  possible we should tear down resources when done.

  .. note::

      Patrole modifies roles dynamically in the background, which affects
      pre-provisioned credentials. Work is currently underway to clean up
      modifications made to pre-provisioned credentials.

* *Self-testing*. Patrole should be self-testing.

.. _Tempest plugin: https://docs.openstack.org/tempest/latest/plugin.html
.. _design principles: https://docs.openstack.org/tempest/latest/overview.html#design-principles
.. _policy in code: https://specs.openstack.org/openstack/oslo-specs/specs/newton/policy-in-code.html
.. _Nova repository: https://github.com/openstack/nova/tree/master/nova/policies
.. _Keystone repository: https://github.com/openstack/keystone/tree/master/keystone/common/policies

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

Terminology
^^^^^^^^^^^
* Expected Result - The expected result of a given test.
* Actual Result - The actual result of a given test.
* Final Result - A match between both expected and actual results. A mismatch
  in the expected result and the actual result will result in a test failure.

  * Expected: Pass | Actual: Pass - Test Case Success
  * Expected: Pass | Actual: Fail - Test Case Under-Permission Failure
  * Expected: Fail | Actual: Pass - Test Case Over-Permission Failure
  * Expected: Fail | Actual: Fail (Expected exception) - Test Case Success
  * Expected: Fail | Actual: Fail (Unexpected exception) - Test Case Failure

Quickstart
----------
To run Patrole, you must first have `Tempest`_ installed and configured
properly. Please reference Tempest's `Quickstart`_ guide to do so. Follow all
the steps outlined therein. Afterward, proceed with the steps below.

#. You first need to install Patrole. This is done with pip after you check out
   the Patrole repo::

    $ git clone https://git.openstack.org/openstack/patrole
    $ pip install patrole/

   This can be done within a venv.

   .. note::

     You may also install Patrole from source code by running::

       pip install -e patrole/

#. Next you must properly configure Patrole, which is relatively
   straightforward. For details on configuring Patrole refer to the
   :ref:`patrole-configuration`.

#. Once the configuration is done you're now ready to run Patrole. This can
   be done using the `tempest_run`_ command. This can be done by running::

     $ tempest run --regex '^patrole_tempest_plugin\.tests\.api'

   There is also the option to use testr directly, or any `testr`_ based test
   runner, like `ostestr`_. For example, from the workspace dir run::

     $ stestr --regex '(?!.*\[.*\bslow\b.*\])(^patrole_tempest_plugin\.tests\.api))'

   will run the same set of tests as the default gate jobs.

   You can also run Patrole tests using `tox`_. To do so, ``cd`` into the
   **Tempest** directory and run::

     $ tox -eall-plugin -- patrole_tempest_plugin.tests.api

   .. note::

     It is possible to run Patrole via ``tox -eall`` in order to run Patrole
     isolated from other plugins. This can be accomplished by including the
     installation of services that currently use policy in code -- for example,
     Nova and Keystone. For example::

       $ tox -evenv-tempest -- pip install /opt/stack/patrole /opt/stack/keystone /opt/stack/nova
       $ tox -eall -- patrole_tempest_plugin.tests.api

#. Log information from tests is captured in ``tempest.log`` under the Tempest
   repository. Some Patrole debugging information is captured in that log
   related to expected test results and :ref:`role-overriding`.

   More detailed RBAC testing log output is emitted to ``patrole.log`` under
   the Patrole repository. To configure Patrole's logging, see the
   :ref:`patrole-configuration` guide.

.. _Tempest: https://github.com/openstack/tempest
.. _Quickstart: https://docs.openstack.org/tempest/latest/overview.html#quickstart
.. _tempest_run: https://docs.openstack.org/tempest/latest/run.html
.. _testr: https://testrepository.readthedocs.org/en/latest/MANUAL.html
.. _ostestr: https://docs.openstack.org/os-testr/latest/
.. _tox: https://tox.readthedocs.io/en/latest/

RBAC Tests
----------

To change the role that the patrole tests are being run as, edit
``rbac_test_role`` in the ``patrole`` section of tempest.conf: ::

    [patrole]
    rbac_test_role = member
    ...

.. note::

  The ``rbac_test_role`` is service-specific. member, for example,
  is an arbitrary role, but by convention is used to designate the default
  non-admin role in the system. Most Patrole tests should be run with
  **admin** and **member** roles. However, other services may use entirely
  different roles.

For more information about the member role and its nomenclature,
please see: `<https://ask.openstack.org/en/question/4759/member-vs-_member_/>`__.

Unit Tests
----------

Patrole also has a set of unit tests which test the Patrole code itself. These
tests can be run by specifying the test discovery path::

  $ stestr --test-path ./patrole_tempest_plugin/tests/unit run

By setting ``--test-path`` option to ``./patrole_tempest_plugin/tests/unit``
it specifies that test discovery should only be run on the unit test directory.

Alternatively, there are the py27 and py35 tox jobs which will run the unit
tests with the corresponding version of Python.

One common activity is to just run a single test; you can do this with tox
simply by specifying to just run py27 or py35 tests against a single test::

  $ tox -e py27 -- -n patrole_tempest_plugin.tests.unit.test_rbac_utils.RBACUtilsTest.test_override_role_with_missing_admin_role

Or all tests in the test_rbac_utils.py file::

  $ tox -e py27 -- -n patrole_tempest_plugin.tests.unit.test_rbac_utils

You may also use regular expressions to run any matching tests::

  $ tox -e py27 -- test_rbac_utils

For more information on these options and details about stestr, please see the
`stestr documentation <http://stestr.readthedocs.io/en/latest/MANUAL.html>`_.

Release Versioning
------------------
`Patrole Release Notes <https://docs.openstack.org/releasenotes/patrole/>`_
shows which changes have been released for each version.

Patrole's release versioning follows Tempest's conventions. Like Tempest,
Patrole is branchless and uses versioning instead.
