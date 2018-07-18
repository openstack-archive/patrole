====================
Enabling in Devstack
====================

.. warning::

  The ``stack.sh`` script must be run in a disposable VM that is not
  being created automatically. See the `README file`_ in the DevStack
  repository for more information.

1. Download DevStack::

     git clone https://git.openstack.org/openstack-dev/devstack.git
     cd devstack

2. Patrole can be installed like any other DevStack plugin by including the
   ``enable_plugin`` directive inside local.conf::

     > cat local.conf
     [[local|localrc]]
     enable_plugin patrole https://git.openstack.org/openstack/patrole

3. Run ``stack.sh`` found in the DevStack repo.

.. _README file: https://github.com/openstack-dev/devstack/blob/master/README.rst
