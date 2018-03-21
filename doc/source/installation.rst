.. _patrole-installation:

==========================
Patrole Installation Guide
==========================

Manual Installation Information
===============================

At the command line::

    $ git clone http://git.openstack.org/openstack/patrole
    $ sudo pip install ./patrole

Or, if you have virtualenvwrapper installed::

    $ mkvirtualenv patrole_env
    $ workon patrole_env
    $ pip install ./patrole

Or to install from the source::

    $ navigate to patrole directory
    $ sudo pip install -e .

DevStack Installation
=====================

Patrole can be installed like any other DevStack plugin by including the
``install_plugin`` directive inside local.conf::

    [[local|localrc]]
    ...

    enable_plugin patrole git://git.openstack.org/openstack/patrole
