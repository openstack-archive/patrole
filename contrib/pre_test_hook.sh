#!/bin/bash -xe
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# This script is executed inside post_test_hook function in devstack gate.
# First argument ($1) expects 'rbac-role' as value for setting appropriate
# tempest rbac option 'rbac_test_role'.

sudo chown -R jenkins:stack $BASE/new/tempest
sudo chown -R jenkins:stack $BASE/data/tempest

# Import devstack function 'iniset'
source $BASE/new/devstack/functions

export TEMPEST_CONFIG=${TEMPEST_CONFIG:-$BASE/new/tempest/etc/tempest.conf}

# First argument is expected to contain value equal either to 'admin' or
# 'member' (both lower-case).
RBAC_ROLE=$1

if [[ "$RBAC_ROLE" == "member" ]]; then
    $RBAC_ROLE = "Member"
fi

# Set rbac_flag=True under [rbac] section in tempest.conf
iniset $TEMPEST_CONFIG rbac rbac_flag True

# Set rbac_test_role=$RBAC_ROLE under [rbac] section in tempest.conf
iniset $TEMPEST_CONFIG rbac rbac_test_role $RBAC_ROLE
