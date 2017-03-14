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

import testtools

from tempest.common import waiters
from tempest import config

from tempest.lib import decorators

from patrole_tempest_plugin import rbac_rule_validation
from patrole_tempest_plugin.tests.api.compute import rbac_base as base

CONF = config.CONF


class MigrateServerRbacTest(base.BaseV2ComputeRbacTest):

    @classmethod
    def setup_clients(cls):
        super(MigrateServerRbacTest, cls).setup_clients()
        cls.client = cls.servers_client
        cls.admin_servers_client = cls.os_adm.servers_client
        cls.hosts_client = cls.os.hosts_client

    def _get_server_details(self, server_id):
        body = self.client.show_server(server_id)['server']
        return body

    def _get_host_for_server(self, server_id):
        return self._get_server_details(server_id)['OS-EXT-SRV-ATTR:host']

    def _get_host_other_than(self, host):
        for target_host in self._get_compute_hostnames():
            if host != target_host:
                return target_host

    def _get_compute_hostnames(self):
        body = self.hosts_client.list_hosts()['hosts']
        return [
            host_record['host_name']
            for host_record in body
            if host_record['service'] == 'compute'
        ]

    def _migrate_server_to(self, server_id, dest_host, volume_backed=False):
        kwargs = dict()
        block_migration = getattr(self, 'block_migration', None)
        if self.block_migration is None:
            kwargs['disk_over_commit'] = False
            block_migration = (CONF.compute_feature_enabled.
                               block_migration_for_live_migration and
                               not volume_backed)
        self.client.live_migrate_server(
            server_id, host=dest_host, block_migration=block_migration,
            **kwargs)

    @testtools.skipUnless(CONF.compute_feature_enabled.cold_migration,
                          'Cold migration not available.')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-migrate-server:migrate")
    @decorators.idempotent_id('c6f1607c-9fed-4c00-807e-9ba675b98b1b')
    def test_cold_migration(self):
        if CONF.compute.min_compute_nodes < 2:
            msg = "Less than 2 compute nodes, skipping multinode tests."
            raise self.skipException(msg)

        server = self.create_test_server(wait_until="ACTIVE")
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self.client.migrate_server(server['id'])
        waiters.wait_for_server_status(self.admin_servers_client,
                                       server['id'], 'VERIFY_RESIZE')

    @testtools.skipUnless(CONF.compute_feature_enabled.live_migration,
                          'Live migration feature is not enabled.')
    @rbac_rule_validation.action(
        service="nova",
        rule="os_compute_api:os-migrate-server:migrate_live")
    @decorators.idempotent_id('33520834-72c8-4edb-a189-a2e0fc9eb0d3')
    def test_migration_live(self):
        if CONF.compute.min_compute_nodes < 2:
            msg = "Less than 2 compute nodes, skipping multinode tests."
            raise self.skipException(msg)

        server_id = self.create_test_server(wait_until="ACTIVE",
                                            volume_backed=False)['id']
        actual_host = self._get_host_for_server(server_id)
        target_host = self._get_host_other_than(actual_host)
        self.rbac_utils.switch_role(self, switchToRbacRole=True)
        self._migrate_server_to(server_id, target_host, volume_backed=False)
        waiters.wait_for_server_status(self.admin_servers_client,
                                       server_id, "ACTIVE")
