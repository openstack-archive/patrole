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
