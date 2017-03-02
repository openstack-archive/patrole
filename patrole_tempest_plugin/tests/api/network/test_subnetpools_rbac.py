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
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions
from tempest import test

from patrole_tempest_plugin import rbac_exceptions
from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.network import rbac_base as base

CONF = config.CONF
LOG = log.getLogger(__name__)


class SubnetPoolsRbacTest(base.BaseNetworkRbacTest):

    @classmethod
    def skip_checks(cls):
        super(SubnetPoolsRbacTest, cls).skip_checks()
        if not test.is_extension_enabled('subnet_allocation', 'network'):
            msg = "subnet_allocation extension not enabled."
            raise cls.skipException(msg)

    def tearDown(self):
        self.rbac_utils.switch_role(self, switchToRbacRole=False)
        super(SubnetPoolsRbacTest, self).tearDown()

    def _create_subnetpool(self, shared=None):
        post_body = {'name': data_utils.rand_name(self.__class__.__name__),
                     'min_prefixlen': 24,
                     'max_prefixlen': 32,
                     'prefixes': [CONF.network.project_network_cidr]}

        if shared is not None:
            post_body['shared'] = shared

        body = self.subnetpools_client.create_subnetpool(**post_body)
        subnetpool = body['subnetpool']

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.subnetpools_client.delete_subnetpool,
                        subnetpool['id'])

        return subnetpool

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_subnetpool")
    @decorators.idempotent_id('1b5509fd-2c32-44a8-a786-1b6ca162dbd1')
    def test_create_subnetpool(self):
        """Create subnetpool.

        RBAC test for the neutron create_subnetpool policy
        """
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_subnetpool()

    @rbac_rule_validation.action(service="neutron",
                                 rule="create_subnetpool:shared")
    @decorators.idempotent_id('cf730989-0d47-40bc-b39a-99e7de484723')
    def test_create_subnetpool_shared(self):
        """Create subnetpool shared.

        RBAC test for the neutron create_subnetpool:shared policy
        """
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._create_subnetpool(shared=True)

    @rbac_rule_validation.action(service="neutron",
                                 rule="get_subnetpool")
    @decorators.idempotent_id('4f5aee26-0507-4b6d-b44c-3128a25094d2')
    def test_show_subnetpool(self):
        """Show subnetpool.

        RBAC test for the neutron get_subnetpool policy
        """
        subnetpool = self._create_subnetpool()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.subnetpools_client.show_subnetpool(subnetpool['id'])
        except exceptions.NotFound as e:
            LOG.info("NotFound exception caught. Exception is thrown when "
                     "role doesn't have access to the endpoint."
                     "This is irregular and should be fixed.")
            raise rbac_exceptions.RbacActionFailed(e)

    @rbac_rule_validation.action(service="neutron",
                                 rule="update_subnetpool")
    @decorators.idempotent_id('1e79cead-5081-4be2-a4f7-484c0f443b9b')
    def test_update_subnetpool(self):
        """Update subnetpool.

        RBAC test for the neutron update_subnetpool policy
        """
        subnetpool = self._create_subnetpool()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.subnetpools_client.update_subnetpool(subnetpool['id'],
                                                  min_prefixlen=24)

    @rbac_rule_validation.action(service="neutron",
                                 rule="delete_subnetpool")
    @decorators.idempotent_id('50f5944e-43e5-457b-ab50-fb48a73f0d3e')
    def test_delete_subnetpool(self):
        """Delete subnetpool.

        RBAC test for the neutron delete_subnetpool policy
        """
        subnetpool = self._create_subnetpool()
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        try:
            self.subnetpools_client.delete_subnetpool(subnetpool['id'])
        except exceptions.NotFound as e:
            LOG.info("NotFound exception caught. Exception is thrown when "
                     "role doesn't have access to the endpoint."
                     "This is irregular and should be fixed.")
            raise rbac_exceptions.RbacActionFailed(e)
