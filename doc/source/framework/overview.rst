RBAC Testing Validation
=======================

.. _framework-overview:

--------
Overview
--------

RBAC testing validation is broken up into 3 stages:

#. "Expected" stage. Determine whether the test should be able to succeed
   or fail based on the test role defined by ``[patrole] rbac_test_role``)
   and the policy action that the test enforces.
#. "Actual" stage. Run the test by calling the API endpoint that enforces
   the expected policy action using the test role.
#. Comparing the outputs from both stages for consistency. A "consistent"
   result is treated as a pass and an "inconsistent" result is treated
   as a failure. "Consistent" (or successful) cases include:

   * Expected result is ``True`` and the test passes.
   * Expected result is ``False`` and the test fails.

   For example, a 200 from the API call and a ``True`` result from
   ``oslo.policy`` or a 403 from the API call and a ``False`` result from
   ``oslo.policy`` are successful results.

   "Inconsistent" (or failing) cases include:

   * Expected result is ``False`` and the test passes. This results in an
     :class:`~rbac_exceptions.RbacOverPermissionException` exception
     getting thrown.
   * Expected result is ``True`` and the test fails. This results in a
     :class:`~rbac_exceptions.RbacOverPermissionException` exception
     getting thrown.

   For example, a 200 from the API call and a ``False`` result from
   ``oslo.policy`` or a 403 from the API call and a ``True`` result from
   ``oslo.policy`` are failing results.

-------------------------------
The RBAC Rule Validation Module
-------------------------------

High-level module that provides the decorator that wraps around Tempest tests
and serves as the entry point for RBAC testing validation. The workflow
described above is ultimately carried out by the decorator.

For more information about this module, please see :ref:`rbac-validation`.

---------------------------
The Policy Authority Module
---------------------------

Module called by :ref:`rbac-validation` to verify whether the test
role is allowed to execute a policy action by querying ``oslo.policy`` with
required test data. The result is used by :ref:`rbac-validation` as the
"Expected" result.

For more information about this module, please see :ref:`policy-authority`.

---------------------
The RBAC Utils Module
---------------------

This module is responsible for handling role switching, the mechanism by which
Patrole is able to set up, tear down and execute APIs using the same set
of credentials. Every RBAC test must perform a role switch even if the role
that is being switched to is admin.

For more information about this module, please see :ref:`rbac-utils`.
