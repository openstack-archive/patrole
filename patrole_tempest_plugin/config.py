#    Copyright (c) 2016 AT&T inc.
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

rbac_group = cfg.OptGroup(name='rbac',
                          title='RBAC testing options')

RbacGroup = [
    cfg.StrOpt('rbac_test_role',
               default='admin',
               help="The current RBAC role against which to run"
                    " Patrole tests."),
    cfg.BoolOpt('rbac_flag',
                default=False,
                help="Enables RBAC tests."),
]
