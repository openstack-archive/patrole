.. _rbac-validation:

RBAC Testing Validation
=======================

--------
Overview
--------

RBAC Testing Validation is broken up into 3 stages:

  1. "Expected" stage. Determine whether the test should be able to succeed
     or fail based on the test role defined by ``[patrole] rbac_test_role``)
     and the policy action that the test enforces.
  2. "Actual" stage. Run the test by calling the API endpoint that enforces
     the expected policy action using the test role.
  3. Comparing the outputs from both stages for consistency. A "consistent"
     result is treated as a pass and an "inconsistent" result is treated
     as a failure. "Consistent" (or successful) cases include:

      * Expected result is ``True`` and the test passes.
      * Expected result is ``False`` and the test fails.

     "Inconsistent" (or failing) cases include:

      * Expected result is ``False`` and the test passes. This results in an
        ``RbacOverPermission`` exception getting thrown.
      * Expected result is ``True`` and the test fails. This results in a
        ``Forbidden`` exception getting thrown.

     For example, a 200 from the API call and a ``True`` result from
     ``oslo.policy`` or a 403 from the API call and a ``False`` result from
     ``oslo.policy`` are successful results.

-------------------------------
The RBAC Rule Validation Module
-------------------------------

High-level module that implements decorator inside which the "Expected" stage
is initiated.

.. automodule:: patrole_tempest_plugin.rbac_rule_validation
   :members:

---------------------------
The Policy Authority Module
---------------------------

Using the Policy Authority Module, policy verification is performed by:

1. Pooling together the default `in-code` policy rules.
2. Overriding the defaults with custom policy rules located in a policy.json,
   if the policy file exists and the custom policy definition is explicitly
   defined therein.
3. Confirming that the policy action -- for example, "list_users" -- exists.
   (``oslo.policy`` otherwise claims that role "foo" is allowed to
   perform policy action "bar", for example, because it defers to the
   "default" policy rule and oftentimes the default can be "anyone allowed").
4. Performing a call with all necessary data to ``oslo.policy`` and returning
   the expected result back to ``rbac_rule_validation`` decorator.

.. automodule:: patrole_tempest_plugin.policy_authority
   :members:
   :special-members:
