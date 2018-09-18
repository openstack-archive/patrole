.. _policy-authority:

Policy Authority Module
=======================

Overview
--------

This module is only called for calculating the "Expected" result if
``[patrole] test_custom_requirements`` is ``False``.

Using the :class:`~patrole_tempest_plugin.policy_authority.PolicyAuthority`
class, policy verification is performed by:

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

When to use
-----------

This :class:`~patrole_tempest_plugin.rbac_authority.RbacAuthority` class
can be used to validate the default OpenStack policy configuration. It
is recommended that this approach be used for RBAC validation for clouds that
use little to no policy customizations or overrides.

This validation approach should be used when:

* Validating the out-of-the-box policy-in-code OpenStack policy configuration.

  It is important that the default OpenStack policy configuration be validated
  before deploying OpenStack into production. Bugs exist in software and the
  earlier they can be caught and prevented (via CI/CD, for example), the
  better. Patrole continues to be used to identify default policy bugs
  across OpenStack services.

* Validating policy reliably and accurately.

  Relying on ``oslo.policy`` to compute the expected test results provides
  accurate tests, without the hassle of having to reinvent the wheel. Since
  OpenStack APIs use ``oslo.policy`` for policy enforcement, it makes sense
  to compute expected results by using the same library, ensuring test
  reliability.

* Continuously validating policy changes to OpenStack projects under
  development by gating them against Patrole CI/CD jobs run by `Zuul`_.

.. _Zuul: https://docs.openstack.org/infra/zuul/

Implementation
--------------

.. automodule:: patrole_tempest_plugin.policy_authority
   :members:
   :undoc-members:
   :special-members:
