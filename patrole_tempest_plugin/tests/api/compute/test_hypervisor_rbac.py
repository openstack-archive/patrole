#    Copyright 2017 AT&T Corporation.
#    All Rights Reserved.
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

from tempest.common import utils
from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base


class HypervisorRbacTest(rbac_base.BaseV2ComputeRbacTest):

    @classmethod
    def skip_checks(cls):
        super(HypervisorRbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-hypervisors', 'compute'):
            msg = "%s skipped as os-hypervisors extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(HypervisorRbacTest, cls).resource_setup()
        cls.hypervisor =\
            cls.hypervisor_client.list_hypervisors()['hypervisors'][0]

    @decorators.idempotent_id('17bbeb9a-e73e-445f-a771-c794448ef562')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-hypervisors"])
    def test_list_hypervisors(self):
        with self.rbac_utils.override_role(self):
            self.hypervisor_client.list_hypervisors()

    @decorators.idempotent_id('36b95c7d-1085-487a-a674-b7c1ca35f520')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-hypervisors"])
    def test_list_hypervisors_with_details(self):
        with self.rbac_utils.override_role(self):
            self.hypervisor_client.list_hypervisors(detail=True)

    @decorators.idempotent_id('8a7f6f9e-34a6-4480-8875-bba566c3a581')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-hypervisors"])
    def test_show_hypervisor(self):
        with self.rbac_utils.override_role(self):
            self.hypervisor_client.show_hypervisor(self.hypervisor['id'])

    @decorators.idempotent_id('ca0e465c-6365-4a7f-ae58-6f8ddbca06c2')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-hypervisors"])
    def test_show_hypervisor_statistics(self):
        with self.rbac_utils.override_role(self):
            self.hypervisor_client.show_hypervisor_statistics()

    @decorators.idempotent_id('109b37c5-91ba-4da5-b2a2-d7618d84406d')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-hypervisors"])
    def test_show_hypervisor_uptime(self):
        with self.rbac_utils.override_role(self):
            self.hypervisor_client.show_hypervisor_uptime(
                self.hypervisor['id'])


class HypervisorMaxv252RbacTest(rbac_base.BaseV2ComputeRbacTest):
    # These tests will fail with a 404 starting from microversion 2.53:
    # See the following links for details:
    # https://developer.openstack.org/api-ref/compute/#list-hypervisor-servers
    # https://developer.openstack.org/api-ref/compute/#search-hypervisor
    max_microversion = '2.52'

    @classmethod
    def skip_checks(cls):
        super(HypervisorMaxv252RbacTest, cls).skip_checks()
        if not utils.is_extension_enabled('os-hypervisors', 'compute'):
            msg = "%s skipped as os-hypervisors extension not enabled." \
                  % cls.__name__
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(HypervisorMaxv252RbacTest, cls).resource_setup()
        cls.hypervisor =\
            cls.hypervisor_client.list_hypervisors()['hypervisors'][0]

    @decorators.idempotent_id('b86f03cf-2e79-4d88-9eea-62f761591413')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-hypervisors"])
    def test_list_servers_on_hypervisor(self):
        with self.rbac_utils.override_role(self):
            self.hypervisor_client.list_servers_on_hypervisor(
                self.hypervisor['hypervisor_hostname'])

    @decorators.idempotent_id('3dbc71c1-8f04-4674-a67c-dcb2fd99b1b4')
    @rbac_rule_validation.action(
        service="nova",
        rules=["os_compute_api:os-hypervisors"])
    def test_search_hypervisor(self):
        with self.rbac_utils.override_role(self):
            self.hypervisor_client.search_hypervisor(
                self.hypervisor['hypervisor_hostname'])
