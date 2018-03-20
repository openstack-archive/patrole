.. _patrole-testing:

===============
Patrole Testing
===============

Testing Scope
=============

Patrole testing scope is strictly confined to Role-Based Access Control
(RBAC). In OpenStack, ``oslo.policy`` is the RBAC library used by all
major services. Thus, Patrole is concerned with validating that public API
endpoints are correctly using ``oslo.policy`` for authorization.

In other words, all tests in Patrole are RBAC tests.

Stable Tests
============

In the discussion below, "correct" means that a test is consistent with
a service's API-to-policy mapping and "stable" means that a test should
require minimal maintenance for the supported releases.

Present
-------

During the Queens release, a `governance spec`_ was pushed to support policy
in code, which documents the mapping between APIs and each of their policies.

This documentation is an important prerequisite for ensuring that Patrole
tests for a given service are correct. This mapping can be referenced to
confirm that Patrole's assumed mapping for a test is correct. For
example, Nova has implemented policy in code which can be used to verify
that Patrole's Nova RBAC tests use the same mapping.

If a given service does not have policy in code, this implies that it is
*more likely* that the RBAC tests for that service are inconsistent with the
*intended* policy mapping. Until that service implements policy in code, it
is difficult for Patrole maintainers to verify that tests for that service
are correct.

Future
------

Once all services that Patrole tests have implemented policy in code --
and once Patrole has updated all its tests in accordance with the policy in
code documentation -- then Patrole tests can guaranteed to be stable.

This stability will be denoted with a 1.0 version release.

.. _governance spec: https://governance.openstack.org/tc/goals/queens/policy-in-code.html
