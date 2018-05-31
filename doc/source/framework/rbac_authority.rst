.. rbac-authority:

RBAC Authority Module
=====================

Overview
--------

This module implements an abstract class that is implemented by the classes
below. Each implementation is used by the :ref:`rbac-validation` framework
to determine each expected test result.

:ref:`policy-authority`
-----------------------

The *default* :class:`~patrole_tempest_plugin.rbac_authority.RbacAuthority`
implementation class which is used for policy validation. Uses ``oslo.policy``
to determine the expected test result.

All Patrole `Zuul`_ gates use this
:class:`~patrole_tempest_plugin.rbac_authority.RbacAuthority` class by default.

.. _Zuul: https://docs.openstack.org/infra/zuul/

:ref:`requirements-authority`
-----------------------------

Optional :class:`~patrole_tempest_plugin.rbac_authority.RbacAuthority`
implementation class which is used for policy validation. It uses a high-level
requirements-driven approach to validating RBAC in Patrole.

Implementation
--------------

.. automodule:: patrole_tempest_plugin.rbac_authority
   :members:
   :undoc-members:
