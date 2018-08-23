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

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.volume import rbac_base


class VolumeHostsV3RbacTest(rbac_base.BaseVolumeRbacTest):

    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume_extension:hosts"])
    @decorators.idempotent_id('64e837f5-5452-4e26-b934-c721ea7a8644')
    def test_list_hosts(self):
        with self.rbac_utils.override_role(self):
            self.volume_hosts_client.list_hosts()

    @decorators.idempotent_id('9ddf321e-788f-4787-b8cc-dfa59e264143')
    @rbac_rule_validation.action(service="cinder",
                                 rules=["volume_extension:hosts"])
    def test_show_host(self):
        hosts = self.volume_hosts_client.list_hosts()['hosts']
        host_names = [host['host_name'] for host in hosts]
        self.assertNotEmpty(host_names, "No available volume host was found, "
                                        "all hosts found were: %s" % hosts)

        with self.rbac_utils.override_role(self):
            self.volume_hosts_client.show_host(host_names[0])
