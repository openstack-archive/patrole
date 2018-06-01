#!/usr/bin/env bash
# Plugin file for Patrole Tempest plugin
# --------------------------------------

# Dependencies:
# ``functions`` file
# ``DEST`` must be defined

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set -o xtrace

function install_patrole_tempest_plugin {
    setup_package $PATROLE_DIR -e

    if [[ ${DEVSTACK_SERIES} == 'pike' ]]; then
        if [[ "$RBAC_TEST_ROLE" == "member" ]]; then
            RBAC_TEST_ROLE="Member"
        fi

        # Policies used by Patrole testing that were changed in a backwards-incompatible way.
        # TODO(felipemonteiro): Remove these once stable/pike becomes EOL.
        iniset $TEMPEST_CONFIG policy-feature-enabled create_port_fixed_ips_ip_address_policy False
        iniset $TEMPEST_CONFIG policy-feature-enabled update_port_fixed_ips_ip_address_policy False
        iniset $TEMPEST_CONFIG policy-feature-enabled limits_extension_used_limits_policy False
        iniset $TEMPEST_CONFIG policy-feature-enabled volume_extension_volume_actions_attach_policy False
        iniset $TEMPEST_CONFIG policy-feature-enabled volume_extension_volume_actions_reserve_policy False
        iniset $TEMPEST_CONFIG policy-feature-enabled volume_extension_volume_actions_unreserve_policy False

        # These policies were removed in Stein but are available in Pike.
        iniset $TEMPEST_CONFIG policy-feature-enabled removed_nova_policies_stein False

        # TODO(cl566n): Policies used by Patrole testing. Remove these once stable/pike becomes EOL.
        iniset $TEMPEST_CONFIG policy-feature-enabled added_cinder_policies_stein False
    fi

    if [[ ${DEVSTACK_SERIES} == 'queens' ]]; then
        if [[ "$RBAC_TEST_ROLE" == "member" ]]; then
            RBAC_TEST_ROLE="Member"
        fi

        # These policies were removed in Stein but are available in Queens.
        iniset $TEMPEST_CONFIG policy-feature-enabled removed_nova_policies_stein False

        # TODO(cl566n): Policies used by Patrole testing. Remove these once stable/queens becomes EOL.
        iniset $TEMPEST_CONFIG policy-feature-enabled added_cinder_policies_stein False
    fi

    if [[ ${DEVSTACK_SERIES} == 'rocky' ]]; then
        # TODO(cl566n): Policies used by Patrole testing. Remove these once stable/rocky becomes EOL.
        iniset $TEMPEST_CONFIG policy-feature-enabled added_cinder_policies_stein False
    fi

    iniset $TEMPEST_CONFIG patrole rbac_test_role $RBAC_TEST_ROLE
}

if is_service_enabled tempest; then
    if [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        echo_summary "Installing Patrole Tempest plugin"
        install_patrole_tempest_plugin
    fi
fi

# Restore xtrace
$XTRACE
