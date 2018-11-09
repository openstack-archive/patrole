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

from oslo_log import log

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base

LOG = log.getLogger(__name__)


class NetworkSegmentsRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(NetworkSegmentsRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('multi-provider', 'network'):
            msg = "multi-provider extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NetworkSegmentsRbacTest, cls).resource_setup()
        # Find the network type that is supported by the current cloud by
        # checking which network type other networks currently have. This is
        # done because there is no tempest.conf option enumerating supported
        # network types.
        networks = cls.networks_client.list_networks()['networks']
        network_types = [n['provider:network_type'] for n in networks
                         if n['provider:network_type'] != 'flat']
        if not network_types:
            raise cls.skipException(
                'Could not find network with provider:network_type that is '
                'not "flat".')
        cls.network_type = network_types[0]

    def _create_network_segments(self):
        segments = [{'provider:network_type': self.network_type},
                    {'provider:network_type': self.network_type}]

        body = self.networks_client.create_network(
            name=data_utils.rand_name(self.__class__.__name__),
            segments=segments)
        network = body['network']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network,
                        network['id'])
        return network

    @rbac_rule_validation.action(service="neutron",
                                 rules=["create_network",
                                        "create_network:segments"])
    @decorators.idempotent_id('9e1d0c3d-92e3-40e3-855e-bfbb72ea6e0b')
    def test_create_network_segments(self):
        """Create network with segments.

        RBAC test for the neutron create_network:segments policy
        """
        with self.rbac_utils.override_role(self):
            self._create_network_segments()

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network", "update_network",
                                        "update_network:segments"],
                                 expected_error_codes=[404, 403, 403])
    @decorators.idempotent_id('0f45232a-7b59-4bb1-9a91-db77d0a8cc9b')
    def test_update_network_segments(self):
        """Update network segments.

        RBAC test for the neutron update_network:segments policy
        """
        network = self._create_network_segments()
        new_segments = [{'provider:network_type': self.network_type}]

        with self.rbac_utils.override_role(self):
            self.networks_client.update_network(network['id'],
                                                segments=new_segments)

    @rbac_rule_validation.action(service="neutron",
                                 rules=["get_network",
                                        "get_network:segments"],
                                 expected_error_codes=[404, 403])
    @decorators.idempotent_id('094ff9b7-0c3b-4515-b19b-b9d2031337bd')
    def test_show_network_segments(self):
        """Show network segments.

        RBAC test for the neutron get_network:segments policy
        """
        network = self._create_network_segments()

        with self.rbac_utils.override_role(self):
            body = self.networks_client.show_network(network['id'],
                                                     fields='segments')
        response_network = body['network']

        # If user does not have access to the network segments attribute,
        # no NotFound or Forbidden exception are thrown.  Instead,
        # the response will have an empty network body only.
        if not response_network:
            LOG.info("NotFound or Forbidden exception are not thrown when "
                     "role doesn't have access to the endpoint. Instead, "
                     "the response will have an empty network body.")
            raise rbac_exceptions.RbacEmptyResponseBody()
