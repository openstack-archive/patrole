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

# Install pip manually.
PATROLE_DIR=$BASE/new/patrole
sudo pip install -e $PATROLE_DIR

# Allow tempest.conf to be modified by Jenkins.
sudo chown -R jenkins:stack $BASE/new/tempest
sudo chown -R jenkins:stack $BASE/data/tempest

TEMPEST_CONFIG=$BASE/new/tempest/etc/tempest.conf
TEMPEST_COMMAND="sudo -H -u tempest tox"

DEVSTACK_GATE_TEMPEST_REGEX="(?!.*\[.*\bslow\b.*\])(^patrole_tempest_plugin\.tests\.api)"
DEVSTACK_MULTINODE_GATE_TEMPEST_REGEX="(?=.*\[.*\bslow\b.*\])(^patrole_tempest_plugin\.tests\.api)"

# Import devstack function 'iniset'.
source $BASE/new/devstack/functions

# Use uuid tokens for faster test runs
KEYSTONE_CONF=/etc/keystone/keystone.conf
iniset $KEYSTONE_CONF token provider uuid
sudo service apache2 restart

# First argument is expected to contain value equal either to 'admin' or
# 'member' (both lower-case).
RBAC_ROLE=$1

if [[ "$RBAC_ROLE" == "member" ]]; then
    RBAC_ROLE="Member"
fi

# Second argument is expected to contain value indicating whether the
# environment is "multinode" or not (empty string).
TYPE=$2

# Set enable_rbac=True under [rbac] section in tempest.conf
iniset $TEMPEST_CONFIG rbac enable_rbac True
# Set rbac_test_role=$RBAC_ROLE under [rbac] section in tempest.conf
iniset $TEMPEST_CONFIG rbac rbac_test_role $RBAC_ROLE
# Set strict_policy_check=False under [rbac] section in tempest.conf
iniset $TEMPEST_CONFIG rbac strict_policy_check False
# Set additional, necessary CONF values
iniset $TEMPEST_CONFIG auth use_dynamic_credentials True
iniset $TEMPEST_CONFIG auth tempest_roles Member
iniset $TEMPEST_CONFIG identity auth_version v3

# Give permissions back to Tempest.
sudo chown -R tempest:stack $BASE/new/tempest
sudo chown -R tempest:stack $BASE/data/tempest

set -o errexit

# cd into Tempest directory before executing tox.
cd $BASE/new/tempest

if [[ "$TYPE" == "multinode" ]]; then
    $TEMPEST_COMMAND -eall-plugin -- $DEVSTACK_MULTINODE_GATE_TEMPEST_REGEX --concurrency=$TEMPEST_CONCURRENCY
else
    $TEMPEST_COMMAND -eall-plugin -- $DEVSTACK_GATE_TEMPEST_REGEX --concurrency=$TEMPEST_CONCURRENCY
fi

sudo -H -u tempest .tox/all-plugin/bin/tempest list-plugins
