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
import yaml

from oslo_log import log as logging

from tempest.lib import exceptions

from patrole_tempest_plugin.rbac_utils import RbacAuthority

LOG = logging.getLogger(__name__)


class RequirementsParser(object):
    _inner = None

    class Inner(object):
        _rbac_map = None

        def __init__(self, filepath):
            with open(filepath) as f:
                RequirementsParser.Inner._rbac_map = \
                    list(yaml.safe_load_all(f))

    def __init__(self, filepath):
        if RequirementsParser._inner is None:
            RequirementsParser._inner = RequirementsParser.Inner(filepath)

    @staticmethod
    def parse(component):
        try:
            for section in RequirementsParser.Inner._rbac_map:
                if component in section:
                    return section[component]
        except yaml.parser.ParserError:
            LOG.error("Error while parsing the requirements YAML file. Did "
                      "you pass a valid component name from the test case?")
        return None


class RequirementsAuthority(RbacAuthority):
    def __init__(self, filepath=None, component=None):
        if filepath is not None and component is not None:
            self.roles_dict = RequirementsParser(filepath).parse(component)
        else:
            self.roles_dict = None

    def allowed(self, rule_name, role):
        if self.roles_dict is None:
            raise exceptions.InvalidConfiguration(
                "Roles dictionary parsed from requirements YAML file is "
                "empty. Ensure the requirements YAML file is correctly "
                "formatted.")
        try:
            _api = self.roles_dict[rule_name]
            return role in _api
        except KeyError:
            raise KeyError("'%s' API is not defined in the requirements YAML "
                           "file" % rule_name)
        return False
