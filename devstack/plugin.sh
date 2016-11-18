#!/bin/bash

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

# devstack/plugin.sh
# Functions to control the configuration of fortigate ml2 plugin

# Dependencies:
#
# ``functions`` file
# ``DEST`` must be defined
# ``STACK_USER`` must be defined

# ``stack.sh`` calls the entry points in this order:

XTRACE=$(set +o | grep xtrace)
set +o xtrace

# Specify the FortiGate parameters
Q_FORTINET_PLUGIN_FG_IP=${Q_FORTINET_PLUGIN_FG_IP:-}
Q_FORTINET_PLUGIN_FG_PORT=${Q_FORTINET_PLUGIN_FG_PORT:-443}
Q_FORTINET_PLUGIN_FG_PROTOCOL=${Q_FORTINET_PLUGIN_FG_PROTOCOL:-https}
# Specify the FG username
Q_FORTINET_PLUGIN_FG_USERNAME=${Q_FORTINET_PLUGIN_FG_USERNAME:-admin}
# Specify the FG passward for above username
Q_FORTINET_PLUGIN_FG_PASSWORD=${Q_FORTINET_PLUGIN_FG_PASSWORD:-''}
# Specify if tunneling is enabled
Q_FORTINET_PLUGIN_ENABLE_TUNNELING=${Q_FORTINET_PLUGIN_ENABLE_TUNNELING:-True}
# Specify physical interface of FortiGate for tenant network
Q_FORTINET_PLUGIN_FG_INT_INF=${Q_FORTINET_PLUGIN_FG_INT_INF:-}
# Specify physical interface of FortiGate for external network
Q_FORTINET_PLUGIN_FG_EXT_INF=${Q_FORTINET_PLUGIN_FG_EXT_INF:-}
# Specify tenant network type on FortiGate
Q_FORTINET_PLUGIN_FG_TENANT_NET_TYPE=${Q_FORTINET_PLUGIN_FG_TENANT_NET_TYPE:-vlan}
# Specify the VLAN range
Q_FORTINET_PLUGIN_VLAN_ID_RANGES=${Q_FORTINET_PLUGIN_VLAN_ID_RANGES:-4000:4094}
# Specify whether hardware npu is available
Q_FORTINET_PLUGIN_NPU_AVAILABLE=${Q_FORTINET_PLUGIN_NPU_AVAILABLE:-True}
# Specify port for tenant network bridge
Q_FORTINET_TENANT_INTERFACE=${Q_FORTINET_TENANT_INTERFACE:-}
# Firewall policy security profiles on FGT
Q_FORTINET_FWAAS_AV_PROFILE=${Q_FORTINET_FWAAS_AV_PROFILE:-}
Q_FORTINET_FWAAS_WEBFILTER_PROFILE=${Q_FORTINET_FWAAS_WEBFILTER_PROFILE:-}
Q_FORTINET_FWAAS_IPS_SENSOR=${Q_FORTINET_FWAAS_IPS_SENSOR:-}
Q_FORTINET_FWAAS_APPLICATION_LIST=${Q_FORTINET_FWAAS_APPLICATION_LIST:-}
Q_FORTINET_FWAAS_SSL_SSH_PROFILE=${Q_FORTINET_FWAAS_SSL_SSH_PROFILE:-}
Q_FORTINET_FWAAS_ENABLE_DEFAULT_FWRULE=${Q_FORTINET_FWAAS_ENABLE_DEFAULT_FWRULE:-True}

# Specify tempest ping timeout
PING_TIMEOUT=${PING_TIMEOUT:-300}

# The project directory
NETWORKING_FGT_DIR=$DEST/networking-fortinet

source $TOP_DIR/lib/neutron_plugins/ml2

function install_fortigate_neutron_ml2_driver {
    cd $NETWORKING_FGT_DIR
    echo "Installing the networking-fortinet driver for Fortigate"
    sudo pip install -e .
}

function configure_fortigate_neutron_ml2_driver {
    # populate the fortinet plugin cfg file with the FG information
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet address $Q_FORTINET_PLUGIN_FG_IP
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet port $Q_FORTINET_PLUGIN_FG_PORT
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        protocol $Q_FORTINET_PLUGIN_FG_PROTOCOL
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        username $Q_FORTINET_PLUGIN_FG_USERNAME
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        password $Q_FORTINET_PLUGIN_FG_PASSWORD
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        int_interface $Q_FORTINET_PLUGIN_FG_INT_INF
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        ext_interface $Q_FORTINET_PLUGIN_FG_EXT_INF
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        tenant_network_type $Q_FORTINET_PLUGIN_FG_TENANT_NET_TYPE
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        vlink_vlan_id_range $Q_FORTINET_PLUGIN_VLAN_ID_RANGES
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        npu_available $Q_FORTINET_PLUGIN_NPU_AVAILABLE
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        av_profile $Q_FORTINET_FWAAS_AV_PROFILE
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        webfilter_profile $Q_FORTINET_FWAAS_WEBFILTER_PROFILE
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        ips_sensor $Q_FORTINET_FWAAS_IPS_SENSOR
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        application_list $Q_FORTINET_FWAAS_APPLICATION_LIST
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        ssl_ssh_profile $Q_FORTINET_FWAAS_SSL_SSH_PROFILE
    iniset /$Q_PLUGIN_CONF_FILE ml2_fortinet \
        enable_default_fwrule $Q_FORTINET_FWAAS_ENABLE_DEFAULT_FWRULE

    if is_service_enabled n-cpu; then
        sudo ovs-vsctl --no-wait -- --may-exist add-br \
            br-${Q_FORTINET_TENANT_INTERFACE}
        sudo ovs-vsctl --no-wait -- --may-exist add-port \
            br-${Q_FORTINET_TENANT_INTERFACE} ${Q_FORTINET_TENANT_INTERFACE}
        sudo ip link set br-${Q_FORTINET_TENANT_INTERFACE} up
        sudo ip link set ${Q_FORTINET_TENANT_INTERFACE} up
    fi
}

function configure_tempest_for_fortigate_plugin {
    # sometimes it can take 3 dhcp discover attempts for vm
    # to get an ip address in our ci system.
    if is_service_enabled tempest; then
        iniset /$TEMPEST_CONFIG compute ping_timeout $PING_TIMEOUT
        iniset /$TEMPEST_CONFIG fortigate enable_default_fwrule $Q_FORTINET_FWAAS_ENABLE_DEFAULT_FWRULE
    fi
}

function has_neutron_plugin_security_group {
    # 1 means False here
    return 1
}

if is_service_enabled fortinet-neutron; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_fortigate_neutron_ml2_driver
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_fortigate_neutron_ml2_driver
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        configure_tempest_for_fortigate_plugin
    fi

    if [[ "$1" == "unstack" ]]; then
        if [[ ! -z $FGT_CONFIG_PATH ]]; then
            ssh -o StrictHostKeyChecking=no -tt $Q_FORTINET_PLUGIN_FG_USERNAME@$Q_FORTINET_PLUGIN_FG_IP << EOF
config global
execute restore config ftp $FGT_CONFIG_PATH $FTP_SERVER $FTP_USER $FTP_PASS
y
exit
EOF
        fi
    fi

    if [[ "$1" == "clean" ]]; then
        # no-op
        :
    fi
fi


$XTRACE
