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

import logging
import os

from oslo_concurrency import lockutils

from tempest import config
from tempest.test_discover import plugins

from patrole_tempest_plugin import config as project_config

RBACLOG = logging.getLogger('rbac_reporting')


class PatroleTempestPlugin(plugins.TempestPlugin):

    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "patrole_tempest_plugin/tests/api"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    @lockutils.synchronized('_reset_log_file')
    def _reset_log_file(self, logfile):
        try:
            os.remove(logfile)
        except OSError:
            pass

    def _configure_per_test_logging(self, conf):
        # Separate log handler for rbac reporting
        RBACLOG.setLevel(level=logging.INFO)
        # Set up proper directory handling
        report_abs_path = os.path.abspath(conf.patrole_log.report_log_path)
        report_path = os.path.join(
            report_abs_path, conf.patrole_log.report_log_name)

        # Remove the log file if it exists
        self._reset_log_file(report_path)

        # Delay=True so that we don't end up creating an empty file if we
        # never log to it.
        rbac_report_handler = logging.FileHandler(
            filename=report_path, delay=True, mode='a')
        rbac_report_handler.setFormatter(
            fmt=logging.Formatter(fmt='%(message)s'))
        RBACLOG.addHandler(rbac_report_handler)

    def register_opts(self, conf):
        config.register_opt_group(
            conf,
            project_config.patrole_group,
            project_config.PatroleGroup)
        config.register_opt_group(
            conf,
            project_config.patrole_log_group,
            project_config.PatroleLogGroup)

        if conf.patrole_log.enable_reporting:
            self._configure_per_test_logging(conf)

    def get_opt_lists(self):
        return [(project_config.patrole_group.name,
                 project_config.PatroleGroup)]
