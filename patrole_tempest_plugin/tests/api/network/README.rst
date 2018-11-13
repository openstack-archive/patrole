.. _network-rbac-tests:

Network RBAC Tests
==================

What are these tests?
---------------------

These tests are RBAC tests for Neutron and its associated plugins. They are
broken up into the following categories:

* :ref:`neutron-rbac-tests`
* :ref:`neutron-extension-rbac-tests`

.. _neutron-rbac-tests:

Neutron tests
^^^^^^^^^^^^^

Neutron RBAC tests inherit from the base class ``BaseNetworkRbacTest``. They
test many of the Neutron policies found in the service's `policy.json file`_.
These tests are gated in many `Zuul jobs`_ (master, n-1, n-2) against many
roles (member, admin).

.. _neutron-extension-rbac-tests:

Neutron extension tests
^^^^^^^^^^^^^^^^^^^^^^^

The Neutron RBAC plugin tests focus on testing RBAC for various Neutron
extensions, or, stated differently: tests that rely on
`neutron-tempest-plugin`_.

These tests inherit from the base class ``BaseNetworkExtRbacTest``. If an
extension or plugin is not enabled in the cloud, the corresponding tests are
gracefully skipped.

.. note::

  Patrole should import as few dependencies from ``neutron_tempest_plugin`` as
  possible (such as ``neutron_tempest_plugin.api.clients`` for the service
  clients) because the module is not a `stable interface`_.

.. _policy.json file: https://github.com/openstack/neutron/blob/master/etc/policy.json
.. _Zuul jobs: https://github.com/openstack/patrole/blob/master/.zuul.yaml
.. _neutron-tempest-plugin: https://github.com/openstack/neutron-tempest-plugin
.. _stable interface: https://github.com/openstack/neutron-tempest-plugin/tree/master/neutron_tempest_plugin#warning
