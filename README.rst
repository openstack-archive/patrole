=======
patrole
=======

Patrole is a tool for verifying that Role-Based Access Control is being enforced.

Patrole allows users to run API tests using specified RBAC roles.  This allows
deployments to verify that only intended roles have access to those APIs.
This is critical to ensure security, especially in large deployments with
custom roles.

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/patrole
* Source: http://git.openstack.org/cgit/openstack/patrole
* Bugs: http://bugs.launchpad.net/patrole

Features
--------

Patrole offers RBAC testing for various OpenStack RBAC policies.  It includes
a decorator that wraps around tests which verifies that when the test calls the
corresponding api endpoint, access is only granted for correct roles.

There are several possible test flows.

If the rbac_test_role is allowed to access the endpoint
 - The test passes if no 403 forbidden or RbacActionFailed exception is raised.

If the rbac_test_role is not allowed to access the endpoint
 - If the endpoint returns a 403 forbidden exception the test will pass
 - If the endpoint returns something other than a 403 forbidden to indicate
   that the role is not allowed, the test will raise an RbacActionFailed exception.
