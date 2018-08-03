# Copyright 2017 AT&T Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.api.network import base as network_base
from tempest import config

from patrole_tempest_plugin import rbac_utils

CONF = config.CONF


class BaseNetworkRbacTest(rbac_utils.RbacUtilsMixin,
                          network_base.BaseNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(BaseNetworkRbacTest, cls).skip_checks()
        cls.skip_rbac_checks()

    @classmethod
    def setup_clients(cls):
        super(BaseNetworkRbacTest, cls).setup_clients()
        cls.setup_rbac_utils()


class BaseNetworkPluginRbacTest(BaseNetworkRbacTest):
    """Base class to be used with tests that require neutron-tempest-plugin.
    """

    @classmethod
    def get_auth_providers(cls):
        """Register auth_provider from neutron-tempest-plugin.
        """
        providers = super(BaseNetworkPluginRbacTest, cls).get_auth_providers()
        if cls.is_neutron_tempest_plugin_avaliable():
            providers.append(cls.ntp_client.auth_provider)
        return providers

    @classmethod
    def skip_checks(cls):
        super(BaseNetworkPluginRbacTest, cls).skip_checks()

        if not cls.is_neutron_tempest_plugin_avaliable():
            msg = ("neutron-tempest-plugin not installed.")
            raise cls.skipException(msg)

    @classmethod
    def is_neutron_tempest_plugin_avaliable(cls):
        try:
            import neutron_tempest_plugin  # noqa
            return True
        except ImportError:
            return False

    @classmethod
    def get_client_manager(cls, credential_type=None, roles=None,
                           force_new=None):
        manager = super(BaseNetworkPluginRbacTest, cls).get_client_manager(
            credential_type=credential_type,
            roles=roles,
            force_new=force_new
        )

        # Import neutron-tempest-plugin clients
        if cls.is_neutron_tempest_plugin_avaliable():
            from neutron_tempest_plugin.api import clients
            neutron_tempest_manager = clients.Manager(manager.credentials)
            cls.ntp_client = neutron_tempest_manager.network_client

        return manager
