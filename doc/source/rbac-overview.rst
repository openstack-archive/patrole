.. _rbac-overview:

==================================
Role-Based Access Control Overview
==================================

Introduction
------------

Role-Based Access Control (RBAC) is used by most OpenStack services to control
user access to resources. Authorization is granted if a user has the necessary
role to perform an action. Patrole is concerned with validating that each of
these resources *can* be accessed by authorized users and *cannot* be accessed
by unauthorized users.

OpenStack services use `oslo.policy`_ as the library for RBAC authorization.
Patrole relies on the same library for deriving expected test results.

.. _policy-in-code:

Policy in Code
--------------

Services publish their policy-to-API mapping via policy in code documentation.
This mapping includes the list of APIs that authorize a policy, for each
policy declared within a service.

For example, Nova's policy in code documentation is located in the
`Nova repository`_ under ``nova/policies``. Likewise, Keystone's policy in
code documentation is located in the `Keystone repository`_ under
``keystone/common/policies``. The other OpenStack services follow the same
directory layout pattern with respect to policy in code.

The policy in code `governance goal`_ enumerates many advantages with following
this RBAC design approach. A so-called library of in-code policies offers the
following advantages, with respect to facilitating validation:

* includes every policy enforced by an OpenStack service, enabling the
  possibility of complete Patrole test coverage for that service (otherwise
  one has to read the source code to discover all the policies)
* provides the policy-to-API mapping for each policy which can be used
  to write correct Patrole tests (otherwise reading source code and
  experimentation are required to derive this mapping)
* by extension, the policy-to-API mapping facilitates writing multi-policy
  Patrole tests (otherwise even more experimentation and code reading is
  required to arrive at all the policies enforced by an API)
* policy in code documentation includes additional information, like
  descriptions and (in the case of some services, like Keystone)
  `scope types`_, which help with understanding how to correctly write
  Patrole tests
* by extension, such information helps to determine whether a Patrole test
  should assume :term:`hard authorization` or :term:`soft authorization`

Policy in Code (Default) Validation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, Patrole validates default OpenStack policies. This is so that
the out-of-the-box defaults are sanity-checked, to ensure that OpenStack
services are secure, from an RBAC perspective, for each release.

Patrole strives to validate RBAC by using the policy in code documentation,
wherever possible. See :ref:`validation-workflow-overview` for more details.

.. _custom-policies:

Custom Policies
---------------

Operators can override policy in code defaults using `policy.yaml`_. While
this allows operators to offer more fine-grained RBAC control to their tenants,
it opens the door to misconfiguration and bugs. Patrole can be used to validate
that custom policy overrides don't break anything and work as expected.

Custom Policy Validation
^^^^^^^^^^^^^^^^^^^^^^^^

While testing default policy behavior is a valid use case, oftentimes default
policies are modified with custom overrides in production. OpenStack's
`policy.yaml`_ documentation claims that "modifying policy can have unexpected
side effects", which is why Patrole was created: to ensure that custom
overrides allow the principle of least privilege to be tailor-made to exact
specifications via policy overrides, without:

* causing unintended side effects (breaking API endpoints, breaking
  cross-service workflows, breaking the policy file itself); or
* resulting in poor RBAC configuration, promoting security vulnerabilities

This has implications on Patrole's :ref:`design-principles`: validating custom
overrides requires the ability to handle arbitrary roles, which requires logic
capable of dynamically determining expected test behavior.

Note that support for custom policies is limited. This is because custom
policies can be arbitrarily complex, requiring that tests be very robust
in order to handle all edge cases.

.. _multiple-policies:

Multiple Policies
-----------------

Behind the scenes, many APIs enforce multiple policies, for many reasons,
including:

* to control complex cross-service workflows;
* to control whether a server is booted from an image or booted from a volume
  (for example);
* to control whether a response body should contain additional information
  conditioned upon successful policy authorization.

This makes `policy in code`_ especially important for policy validation: it
is difficult to keep track of all the policies being enforced across all the
individual APIs, without policy in code documentation.

Multi-Policy Validation
^^^^^^^^^^^^^^^^^^^^^^^

Patrole offers support for validating APIs that enforce multiple policies.
Perhaps in an ideal world each API endpoint would enforce only one policy,
but in reality some API endpoints enforce multiple policies. Thus, to offer
accurate validation, Patrole handles multiple policies:

* for services *with* policy in code documentation: this documentation
  indicates that a single API endpoint enforces multiple policy actions.
* for services *without* policy in code documentation: the API code clearly
  shows multiple policy actions being validated. Note that in this case some
  degree of log tracing is required by developers to confirm that the expected
  policies are getting enforced, prior to the tests getting merged.

For more information, see :ref:`multi-policy-validation`.

.. _policy-error-codes:

Error Codes
-----------

Most OpenStack services raise a ``403 Forbidden`` following failed
:term:`hard authorization`. Neutron, however, can raise a ``404 NotFound``
as well. See Neutron's `authorization policy enforcement`_ documentation
for more details.

Admin Context Policy
--------------------

The so-called "admin context" policy refers to the following policy definition
(using the legacy policy file syntax):

.. code-block:: javascript

  {
    "context_is_admin": "role:admin"
    ...
  }

Which is unfortunately used to bypass ``oslo.policy`` authorization checks,
for example:

.. code-block:: python

  # This function is responsible for calling oslo.policy to check whether
  # requests are authorized to perform an API action.
  def enforce(context, action, target, [...]):
    # Here this condition, if True, skips over the enforce call below which
    # is what calls oslo.policy.
    if context.is_admin:
        return True
    _ENFORCER.enforce([...])  # This is what can be skipped over.
    [...]

This type of behavior is currently present in many services. Unless such
logic is removed in the future for services that implement it, Patrole
won't really be able to validate that admin role works from an ``oslo.policy``
perspective.

Glossary
--------

The following nomenclature is used throughout Patrole documentation so it is
important to understand what each term means in order to understand concepts
related to RBAC in Patrole.

.. glossary::

  authorize

    The act of ``oslo.policy`` determining whether a user can perform a
    :term:`policy` given his or her :term:`role`.

  enforce

    See :term:`authorize`.

  hard authorization

    The `do_raise`_ flag controls whether policy authorization should result
    in an exception getting raised or a boolean value getting returned.
    Hard authorization results in an exception getting raised. Usually, this
    results in a ``403 Forbidden`` getting returned for unauthorized requests.
    (See :ref:`policy-error-codes` for further details.)

    Related term: :term:`soft authorization`.

  oslo.policy

    The OpenStack library providing support for RBAC policy enforcement across
    all OpenStack services. See the `official documentation`_ for more
    information.

  policy

    Defines an RBAC rule. Each policy is defined by a one-line statement in
    the form "<target>" : "<rule>". For more information, reference OpenStack's
    `policy documentation`_.

  policy action

    See :term:`policy target`.

  policy file

    Prior to `governance goal`_ used by all OpenStack services to define
    policy defaults. Still used by some services, which is why Patrole
    needs to read the policy files to derive policy information for testing.

  policy in code

    Registers default OpenStack policies for a service in the service's code
    base.

    Beginning with the Queens release, policy in code became a
    `governance goal`_.

  policy rule

    The policy rule determines under which circumstances the API call is
    permitted.

  policy target

    The name of a policy.

  requirements file

    Requirements-driven approach to declaring the expected RBAC test results
    referenced by Patrole. Uses a high-level YAML syntax to crystallize policy
    requirements concisely and unambiguously. See :ref:`requirements-authority`
    for more information.

  role

    A designation for the set of actions that describe what a user can do in
    the system. Roles are managed through the `Keystone Roles API`_.

  Role-Based Access Control (RBAC)

    May be formally defined as "an approach to restricting system access to
    authorized users."

  rule

    See :term:`policy rule`. Note that currently the Patrole code base
    conflates "rule" with :term:`policy target` in some places.

  soft authorization

    The `do_raise`_ flag controls whether policy authorization should result
    in an exception getting raised or a boolean value getting returned.
    Soft authorization results in a boolean value getting returned. When policy
    authorization evaluates to true, additional operations are performed as a
    part of the API request or additional information is included in the
    response body (see `response filtering`_ for an example).

    Related term: :term:`hard authorization`.

.. _Nova repository: https://git.openstack.org/cgit/openstack/nova/tree/nova/policies
.. _Keystone repository: https://git.openstack.org/cgit/openstack/keystone/tree/keystone/common/policies
.. _governance goal: https://governance.openstack.org/tc/goals/queens/policy-in-code.html
.. _scope types: https://docs.openstack.org/keystone/latest/admin/tokens-overview.html#authorization-scopes
.. _policy.yaml: https://docs.openstack.org/ocata/config-reference/policy-yaml-file.html
.. _oslo.policy: https://docs.openstack.org/oslo.policy/latest/
.. _policy documentation: https://docs.openstack.org/kilo/config-reference/content/policy-json-file.html
.. _do_raise: https://docs.openstack.org/oslo.policy/latest/reference/api/oslo_policy.policy.html#oslo_policy.policy.Enforcer.enforce
.. _authorization policy enforcement: https://docs.openstack.org/neutron/latest/contributor/internals/policy.html
.. _official documentation: https://docs.openstack.org/oslo.policy/latest/
.. _Keystone Roles API: https://docs.openstack.org/api-ref/identity/v3/#roles
.. _response filtering: https://docs.openstack.org/neutron/latest/contributor/internals/policy.html#response-filtering
