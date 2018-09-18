.. _rbac-validation:

RBAC Rule Validation Module
===========================

Overview
--------

Module that implements the decorator which serves as the entry point for
RBAC validation testing. The decorator should be applied to every RBAC test
with the appropriate ``service`` (OpenStack service) and ``rule`` (OpenStack
policy name defined by the ``service``).

Implementation
--------------

.. automodule:: patrole_tempest_plugin.rbac_rule_validation
   :members:
   :private-members:
   :special-members:
