.. _policy-authority:

Policy Authority Module
=======================

Overview
--------

This module is only called for calculating the "Expected" result if
``[patrole] test_custom_requirements`` is ``False``.

Using the Policy Authority Module, policy verification is performed by:

#. Pooling together the default `in-code` policy rules.
#. Overriding the defaults with custom policy rules located in a policy.json,
   if the policy file exists and the custom policy definition is explicitly
   defined therein.
#. Confirming that the policy action -- for example, "list_users" -- exists.
   (``oslo.policy`` otherwise claims that role "foo" is allowed to
   perform policy action "bar", for example, because it defers to the
   "default" policy rule and oftentimes the default can be "anyone allowed").
#. Performing a call with all necessary data to ``oslo.policy`` and returning
   the expected result back to ``rbac_rule_validation`` decorator.

Implementation
--------------

.. automodule:: patrole_tempest_plugin.policy_authority
   :members:
   :special-members:
