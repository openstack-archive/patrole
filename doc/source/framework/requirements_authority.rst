.. _requirements-authority:

Requirements Authority Module
=============================

Overview
--------

Requirements-driven approach to declaring the expected RBAC test results
referenced by Patrole. Uses a high-level YAML syntax to crystallize policy
requirements concisely and unambiguously.

.. note::

    The :ref:`custom-requirements-file` is required to use this validation
    approach and, currently, must be manually generated.

This validation approach can be toggled on by setting the
``[patrole].test_custom_requirements`` configuration option to ``True``;
see :ref:`patrole-configuration` for more information.

When to use
-----------

This :class:`~patrole_tempest_plugin.rbac_authority.RbacAuthority` class
can be used to achieve a requirements-driven approach to validating an
OpenStack cloud's RBAC implementation. Using this approach, Patrole computes
expected test results by performing lookups against a
:ref:`custom-requirements-file` which precisely defines the cloud's RBAC
requirements.

Using a high-level declarative language, the requirements are captured
unambiguously in the :ref:`custom-requirements-file`, allowing operators to
validate their requirements against their OpenStack cloud.

This validation approach should be used when:

* The cloud has heavily customized policy files that require careful validation
  against one's requirements.

  Heavily customized policy files can contain relatively nuanced/technical
  syntax that impinges upon the goal of using a clear and concise syntax
  present in the :ref:`custom-requirements-file` to drive RBAC validation.

* The cloud has non-OpenStack services that require RBAC validation but which
  don't leverage the ``oslo.policy`` framework.

  Services like `Contrail`_ that are present in an OpenStack-based cloud that
  interface with OpenStack services like Neutron also require RBAC validation.
  The requirements-driven approach to RBAC validation is framework-agnostic
  and so can work with any policy engine.

* Expected results are captured as clear-cut, unambiguous requirements.

  Validating a cloud's RBAC against high-level, clear-cut requirements is
  a valid use case. Relying on ``oslo.policy`` validating customized policy
  files is not sufficient to satisfy this use case.

As mentioned above, the trade-off with this approach is having to manually
generate the :ref:`custom-requirements-file`. There is currently no
tooling to automatically do this.

.. _Contrail: https://github.com/Juniper/contrail-controller/wiki/RBAC

.. _custom-requirements-file:

Custom Requirements File
^^^^^^^^^^^^^^^^^^^^^^^^

File path of the YAML file that defines your RBAC requirements. This
file must be located on the same host that Patrole runs on. The YAML
file should be written as follows:

.. code-block:: yaml

    <service_foo>:
      <api_action_a>:
        - <allowed_role_1>
        - <allowed_role_2>
        - <allowed_role_3>
      <api_action_b>:
        - <allowed_role_2>
        - <allowed_role_4>
    <service_bar>:
      <api_action_c>:
        - <allowed_role_3>

Where:

service = the service that is being tested (Cinder, Nova, etc.).

api_action = the policy action that is being tested. Examples:

* volume:create
* os_compute_api:servers:start
* add_image

allowed_role = the ``oslo.policy`` role that is allowed to perform the API.

Implementation
--------------

.. automodule:: patrole_tempest_plugin.requirements_authority
   :members:
   :undoc-members:
