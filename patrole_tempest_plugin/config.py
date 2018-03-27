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

from oslo_config import cfg


patrole_group = cfg.OptGroup(name='patrole', title='Patrole Testing Options')


PatroleGroup = [
    cfg.StrOpt('rbac_test_role',
               default='admin',
               help="""The current RBAC role against which to run Patrole
tests."""),
    cfg.BoolOpt('enable_rbac',
                default=True,
                help="Enables RBAC tests."),
    # TODO(rb560u): There needs to be support for reading these JSON files from
    # other hosts. It may be possible to leverage the v3 identity policy API.
    cfg.ListOpt('custom_policy_files',
                default=['/etc/%s/policy.json'],
                help="""List of the paths to search for policy files. Each
policy path assumes that the service name is included in the path once. Also
assumes Patrole is on the same host as the policy files. The paths should be
ordered by precedence, with high-priority paths before low-priority paths. The
first path that is found to contain the service's policy file will be used.
"""),
    cfg.BoolOpt('test_custom_requirements',
                default=False,
                help="""
This option determines whether Patrole should run against a
`custom_requirements_file` which defines RBAC requirements. The
purpose of setting this flag to True is to verify that RBAC policy
is in accordance to requirements. The idea is that the
`custom_requirements_file` perfectly defines what the RBAC requirements are.

Here are the possible outcomes when running the Patrole tests against
a `custom_requirements_file`:

YAML definition: allowed
test run: allowed
test result: pass

YAML definition: allowed
test run: not allowed
test result: fail (under-permission)

YAML definition: not allowed
test run: allowed
test result: fail (over-permission)
"""),
    cfg.StrOpt('custom_requirements_file',
               help="""
File path of the yaml file that defines your RBAC requirements. This
file must be located on the same host that Patrole runs on. The yaml
file should be written as follows:

```
<service>:
  <api_action>:
    - <allowed_role>
    - <allowed_role>
    - <allowed_role>
  <api_action>:
    - <allowed_role>
    - <allowed_role>
<service>
  <api_action>:
    - <allowed_role>
```
Where:
service = the service that is being tested (cinder, nova, etc)
api_action = the policy action that is being tested. Examples:
             - volume:create
             - os_compute_api:servers:start
             - add_image
allowed_role = the Keystone role that is allowed to perform the API
""")
]


patrole_log_group = cfg.OptGroup(
    name='patrole_log', title='Patrole Logging Options')

PatroleLogGroup = [
    cfg.BoolOpt('enable_reporting',
                default=False,
                help="Enables reporting on RBAC expected and actual test "
                     "results for each Patrole test"),
    cfg.StrOpt('report_log_name',
               default='patrole.log',
               help="Name of file where output from 'enable_reporting' is "
                    "logged. Note that this file is recreated on each "
                    "invocation of patrole"),
    cfg.StrOpt('report_log_path',
               default='.',
               help="Path (relative or absolute) where the output from "
                    "'enable_reporting' is logged. This is combined with"
                    "report_log_name to generate the full path."),
]


def list_opts():
    """Return a list of oslo.config options available.

    The purpose of this is to allow tools like the Oslo sample config file
    generator to discover the options exposed to users.
    """
    opt_list = [
        (patrole_group, PatroleGroup),
        (patrole_log_group, PatroleLogGroup)
    ]

    return opt_list
