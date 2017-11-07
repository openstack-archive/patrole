#!/usr/bin/env bash
# Plugin file for Patrole Tempest plugin
# --------------------------------------

# Dependencies:
# ``functions`` file
# ``DEST`` must be defined

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace

function install_patrole_tempest_plugin() {
    if is_service_enabled tempest; then
        setup_package $PATROLE_DIR -e

        if [[ "$RBAC_TEST_ROLE" == "member" ]]; then
            RBAC_TEST_ROLE="Member"
        fi

        iniset $TEMPEST_CONFIG rbac enable_rbac True
        iniset $TEMPEST_CONFIG rbac rbac_test_role $RBAC_TEST_ROLE
    fi
}

if is_service_enabled tempest; then
    if [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        echo_summary "Installing Patrole Tempest plugin"
        install_patrole_tempest_plugin
    fi
fi

# Restore xtrace
$XTRACE
