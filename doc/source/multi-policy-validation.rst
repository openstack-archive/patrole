.. _multi-policy-validation:

=======================
Multi-policy Validation
=======================

Introduction
------------

Multi-policy validation exists in Patrole because if one policy were assumed,
then tests could fail because they would not consider all the policies actually
being enforced. The reasoning can be found in `this spec`_. Basically,
since Patrole derives the expected test result dynamically in order to test any
role, each policy enforced by the API under test must be considered to derive
an accurate expected test result, or else the expected and actual test
results will not always match, resulting in overall test failure. For more
information about Patrole's RBAC validation work flow, reference
:ref:`rbac-validation`.

Multi-policy support allows Patrole to more accurately offer RBAC tests for API
endpoints that enforce multiple policy actions.

.. _this spec: http://specs.openstack.org/openstack/qa-specs/specs/patrole/rbac-testing-multiple-policies.html

Scope
-----

Multiple policies should be applied only to tests that require them. Not all
API endpoints enforce multiple policies. Some services consistently enforce
1 policy per API, while on the other side of the spectrum, services like
Neutron have much more involved policy enforcement work flows. See
:ref:`neutron-multi-policy-validation` for more information.

.. _neutron-multi-policy-validation:

Neutron Multi-policy Validation
-------------------------------

Neutron can raise different :ref:`policy-error-codes` following failed policy
authorization. Many endpoints in Neutron enforce multiple policies, which
complicates matters when trying to determine whether the endpoint raises a
403 or a 404 following unauthorized access.

Multi-policy Examples
---------------------

General Examples
^^^^^^^^^^^^^^^^

Below is an example of multi-policy validation for a carefully chosen Nova API:

.. code-block:: python

  @rbac_rule_validation.action(
  service="nova",
  rules=["os_compute_api:os-lock-server:unlock",
         "os_compute_api:os-lock-server:unlock:unlock_override"])
  @decorators.idempotent_id('40dfeef9-73ee-48a9-be19-a219875de457')
  def test_unlock_server_override(self):
      """Test force unlock server, part of os-lock-server.

      In order to trigger the unlock:unlock_override policy instead
      of the unlock policy, the server must be locked by a different
      user than the one who is attempting to unlock it.
      """
      self.os_admin.servers_client.lock_server(self.server['id'])
      self.addCleanup(self.servers_client.unlock_server, self.server['id'])

      with self.override_role():
          self.servers_client.unlock_server(self.server['id'])

While the ``expected_error_codes`` parameter is omitted in the example above,
Patrole automatically populates it with a 403 for each policy in ``rules``.
Therefore, in the example above, the following expected error codes/rules
relationship is observed:

* "os_compute_api:os-lock-server:unlock" => 403
* "os_compute_api:os-lock-server:unlock:unlock_override"  => 403

Below is an example that uses ``expected_error_codes`` to account for the
fact that Neutron is expected to raise a ``404`` on the first policy that
is enforced server-side ("get_port"). Also, in this example, soft authorization
is performed, meaning that it is necessary to check the response body for an
attribute that is added only following successful policy authorization.

.. code-block:: python

    @utils.requires_ext(extension='binding', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_port",
                                        "get_port:binding:vif_type"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('125aff0b-8fed-4f8e-8410-338616594b06')
    def test_show_port_binding_vif_type(self):

        # Verify specific fields of a port
        fields = ['binding:vif_type']

        with self.override_role():
            retrieved_port = self.ports_client.show_port(
                self.port['id'], fields=fields)['port']

        # Rather than throwing a 403, the field is not present, so raise exc.
        if fields[0] not in retrieved_port:
            raise rbac_exceptions.RbacMalformedResponse(
                attribute='binding:vif_type')

Note that in the example above, failure to authorize
"get_port:binding:vif_type" results in the response body getting successfully
returned by the server, but without additional dictionary keys. If Patrole
fails to find those expected keys, it *acts as though* a 403 was thrown (by
raising an exception itself, the ``rbac_rule_validation`` decorator handles
the rest).

Neutron Examples
^^^^^^^^^^^^^^^^

A basic Neutron example that only expects 403's to be raised:

.. code-block:: python

    @utils.requires_ext(extension='external-net', service='network')
    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_network",
                                        "create_network:router:external"],
                                 expected_error_codes=[403, 403])
    @decorators.idempotent_id('51adf2a7-739c-41e0-8857-3b4c460cbd24')
    def test_create_network_router_external(self):

        """Create External Router Network Test

        RBAC test for the neutron create_network:router:external policy
        """
        with self.override_role():
            self._create_network(router_external=True)

Note that above the following expected error codes/rules relationship is
observed:

* "create_network" => 403
* "create_network:router:external"  => 403

A more involved example that expects a 404 to be raised, should the first
policy under ``rules`` fail authorization, and a 403 to be raised for any
subsequent policy authorization failure:

.. code-block:: python

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network",
                                        "update_network",
                                        "update_network:shared"],
                                 expected_error_codes=[404, 403, 403])
    @decorators.idempotent_id('37ea3e33-47d9-49fc-9bba-1af98fbd46d6')
    def test_update_network_shared(self):

        """Update Shared Network Test

        RBAC test for the neutron update_network:shared policy
        """
        with self.override_role():
            self._update_network(shared_network=True)
        self.addCleanup(self._update_network, shared_network=False)

Note that above the following expected error codes/rules relationship is
observed:

* "get_network" => 404
* "update_network"  => 403
* "update_network:shared" => 403

Limitations
-----------

Multi-policy validation in RBAC tests comes with limitations, due to technical
and practical challenges.

Technically, there are challenges associated with multiple policies across
cross-service API communication in OpenStack, such as between Nova and Cinder
or Nova and Neutron. The current framework does not account for these
cross-service policy enforcement workflows, and it is still up for debate
whether it should.

Practically, it is not possible to enumerate every policy enforced by every API
in Patrole, as the maintenance overhead would be huge.

.. _Neutron policy documentation: https://docs.openstack.org/neutron/pike/contributor/internals/policy.html
