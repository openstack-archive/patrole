.. _rbac_field_guide:

Patrole Field Guide to RBAC Tests
=================================


What are these tests?
---------------------

Patrole's primary responsibility is to ensure that your OpenStack cloud
has properly configured Role-Based Access Control (RBAC). All Patrole
tests cases are devoted to this responsibility. Tempest API clients
and utility functions are leveraged to accomplish this goal, but such
functionality is secondary to RBAC validation.

Like Tempest, Patrole not only tests expected positive paths for RBAC
validation, but also -- and more importantly -- negative paths. While
Patrole could be thought of as validating RBAC, it more importantly
verifies that your OpenStack cloud is secure from the perspective of
RBAC (there are many gotchas when it comes to security, not just RBAC).

Negative paths are arguably more important than positive paths when it
comes to RBAC and by extension security, because it is essential that
your cloud be secure from unauthorized access. For example, while it is
important to verify that the admin role has access to admin-level
functionality, it is of critical importance to verify that non-admin roles
*do not* have access to such functionality.

Unlike Tempest, Patrole accomplishes negative testing implicitly -- by
abstracting it away in the background. Patrole dynamically determines
whether a role should have access to an API depending on your cloud's
policy configuration and then confirms whether that is true or false.


Why are these tests in Patrole?
-------------------------------

These tests constitute the core mission in Patrole: to verify RBAC. These
tests are mainly intended to validate RBAC, but can also *unofficially*
be used to discover the policy-to-API mapping for an OpenStack component.

It could be argued that some of these tests could be implemented in
the projects themselves, but that approach has the following shortcomings:

* The projects do not validate RBAC from an integration testing perspective.
* By extension, RBAC across cross-service communication is not usually
  validated.
* The projects' tests do not pass all the metadata to ``oslo.policy`` that is
  in reality passed by the deployed server to that library to determine
  whether a given user is authorized to perform an API action.
* The projects do not exhaustively do RBAC testing for all positive and
  negative paths.
* Patrole is designed to work with any role via configuration settings, but
  on the other hand the projects handpick which roles to test.

Why not use Patrole framework on Tempest tests?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Patrole framework can't be applied to existing Tempest tests via
:ref:`rbac-validation`, because:

* Tempest tests aren't factored the right way: They're not granular enough.
  They call too many APIs and too many policies are enforced by each test.
* Tempest tests assume default policy rules: Tempest uses ``os_admin``
  `credentials`_ for admin APIs and ``os_primary`` for non-admin APIs.
  This breaks for custom policy overrides.
* Tempest doesn't have tests that enforce all the policy actions, regardless.
  Some RBAC tests require that tests be written a very precise way for the
  server to authorize the expected policy actions.

Why are these tests not in Tempest?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Patrole should be a separate project that specializes in RBAC tests. This
was agreed upon during `discussion`_ that led to the approval of the RBAC
testing framework `spec`_, which was the genesis for Patrole.

Philosophically speaking:

* Tempest supports `API and scenario testing`_. RBAC testing is out of scope.
* The `OpenStack project structure reform`_ evolved OpenStack "to a more
  decentralized model where [projects like QA] provide processes and tools to
  empower projects to do the work themselves". This model resulted in the
  creation of the `Tempest external plugin interface`_.
* Tempest supports `plugins`_. Why not use one for RBAC testing?

Practically speaking:

* The Tempest team should not be burdened with having to support Patrole, too.
  Tempest is a big project and having to absorb RBAC testing is difficult.
* Tempest already has many in-tree Zuul checks/gates. If Patrole tests lived
  in Tempest, then adding more Zuul checks/gates for Patrole would only make it
  harder to get changes merged in Tempest.

.. _credentials: https://docs.openstack.org/tempest/latest/write_tests.html#allocating-credentials
.. _discussion: https://review.openstack.org/#/c/382672/
.. _spec: https://specs.openstack.org/openstack/qa-specs/specs/tempest/rbac-policy-testing.html
.. _API and scenario testing: https://docs.openstack.org/tempest/latest/overview.html#tempest-the-openstack-integration-test-suite
.. _OpenStack project structure reform: https://governance.openstack.org/tc/resolutions/20141202-project-structure-reform-spec.html#impact-for-horizontal-teams
.. _Tempest external plugin interface: https://specs.openstack.org/openstack/qa-specs/specs/tempest/implemented/tempest-external-plugin-interface.html
.. _plugins: https://docs.openstack.org/tempest/latest/plugin.html


Scope of these tests
--------------------

RBAC tests should always use the Tempest implementation of the
OpenStack API, to take advantage of Tempest's stable library.

Each test should test a specific API endpoint and the related policy.

Each policy should be tested in isolation of one another -- or at least
as close to this rule as possible -- to ensure proper validation of RBAC.

Each test should be able to work for positive and negative paths.

All tests should be able to be run on their own, not depending on the
state created by a previous test.
