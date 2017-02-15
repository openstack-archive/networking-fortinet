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

PUBLIC_BRIDGE=${PUBLIC_BRIDGE:-br-ex}
PUBLIC_BRIDGE_MTU=${PUBLIC_BRIDGE_MTU:-1500}

# Specify the FortiGate parameters
Q_FORTINET_PLUGIN_FG_IP=${Q_FORTINET_PLUGIN_FG_IP:-169.254.254.100}
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

# create a nat network for the fgtvm management plane in DVR mode.
FGT_BR=fgt-br
FGT_MGMT_NET=fgt-mgmt
VM=fortivm
IMG_DIR=/var/lib/libvirt/images

# if the node is for dvr or fgt host is not specified, boostrap a built-in fortivm
_use_builtin_vm=false
if [[ $Q_DVR_MODE != "legacy" ]] && is_service_enabled n-cpu; then
    _use_builtin_vm=true
fi
if [[ $Q_FORTINET_PLUGIN_FG_IP == "169.254.254.100" ]] && is_service_enabled n-api; then
    _use_builtin_vm=true
fi

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

    if is_service_enabled n-cpu || [[ $Q_FORTINET_PLUGIN_FG_IP == "169.254.254.100" ]]; then
        sudo ovs-vsctl --no-wait -- --may-exist add-br \
            br-${Q_FORTINET_TENANT_INTERFACE}
        sudo ip link set br-${Q_FORTINET_TENANT_INTERFACE} up
        if ! [[ $Q_FORTINET_TENANT_INTERFACE =~ "test" ]]; then
            sudo ovs-vsctl --no-wait -- --may-exist add-port \
                br-${Q_FORTINET_TENANT_INTERFACE} ${Q_FORTINET_TENANT_INTERFACE}
            sudo ip link set ${Q_FORTINET_TENANT_INTERFACE} up
        fi
        iniset /$Q_PLUGIN_CONF_FILE ovs of_interface ovs-ofctl
    fi
}

function configure_tempest_for_fortigate_plugin {
    # sometimes it can take 3 dhcp discover attempts for vm
    # to get an ip address in our ci system.
    iniset /$TEMPEST_CONFIG validation ping_timeout $PING_TIMEOUT
    iniset /$TEMPEST_CONFIG fortigate enable_default_fwrule $Q_FORTINET_FWAAS_ENABLE_DEFAULT_FWRULE
}

function has_neutron_plugin_security_group {
    # 1 means False here
    return 1
}

function configure_builtin_fortivm {
        echo "create bridge"
        cat > $NETWORKING_FGT_DIR/devstack/$FGT_MGMT_NET.xml << EOF
<network>
  <name>$FGT_MGMT_NET</name>
  <bridge name="$FGT_BR"/>
  <forward mode="nat"/>
  <ip address="169.254.254.1" netmask="255.255.255.0">
    <dhcp>
      <range start="169.254.254.100" end="169.254.254.254"/>
    </dhcp>
  </ip>
</network>
EOF
        sudo virsh net-define $NETWORKING_FGT_DIR/devstack/$FGT_MGMT_NET.xml
        sudo virsh net-start $FGT_MGMT_NET
        sudo virsh net-autostart $FGT_MGMT_NET
        _neutron_ovs_base_add_public_bridge
        if [[ $PUBLIC_INTERFACE =~ "test" ]]; then
            # use localhost network and configure snat
            sudo ip addr add dev $PUBLIC_BRIDGE $PUBLIC_NETWORK_GATEWAY/24
            sudo iptables -A FORWARD -d $FLOATING_RANGE -o $PUBLIC_BRIDGE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            sudo iptables -A FORWARD -s $FLOATING_RANGE -i $PUBLIC_BRIDGE -j ACCEPT
            sudo iptables -A FORWARD -i $PUBLIC_BRIDGE -o $PUBLIC_BRIDGE -j ACCEPT
            sudo iptables -t nat -A POSTROUTING -s $FLOATING_RANGE -d 224.0.0.0/24 -j RETURN
            sudo iptables -t nat -A POSTROUTING -s $FLOATING_RANGE -d 255.255.255.255/32 -j RETURN
            sudo iptables -t nat -A POSTROUTING -s $FLOATING_RANGE ! -d $FLOATING_RANGE -p tcp -j MASQUERADE --to-ports 1024-65535
            sudo iptables -t nat -A POSTROUTING -s $FLOATING_RANGE ! -d $FLOATING_RANGE -p udp -j MASQUERADE --to-ports 1024-65535
            sudo iptables -t nat -A POSTROUTING -s $FLOATING_RANGE ! -d $FLOATING_RANGE -j MASQUERADE
        else
            # use provider network
            sudo ovs-vsctl --no-wait -- --may-exist add-port $PUBLIC_BRIDGE $PUBLIC_INTERFACE
            sudo ip link set $PUBLIC_INTERFACE up
        fi
        sudo ip link set $PUBLIC_BRIDGE up
        echo "preparing config drive"
        cat > $NETWORKING_FGT_DIR/devstack/cloud_init/openstack/content/0000 << EOF
$Q_FORTINET_FORTIVM_LIC
EOF
        genisoimage -output $TOP_DIR/disk.config -ldots -allow-lowercase \
-allow-multidot -l -volid cidata -joliet -rock -V config-2 $NETWORKING_FGT_DIR/devstack/cloud_init
        # update the VM data
        yes | sudo wget $Q_FORTINET_IMAGE_URL -O $IMG_DIR/fortios.qcow2
        yes | sudo cp $TOP_DIR/disk.config $IMG_DIR/disk.config

        # create VM with the updated data
        cat $NETWORKING_FGT_DIR/devstack/templates/libvirt.xml | sed 's/$OVS_PHYSICAL_BRIDGE/'"br-$Q_FORTINET_TENANT_INTERFACE"'/' > $TOP_DIR/libvirt.xml
        sudo virsh define $TOP_DIR/libvirt.xml
        sudo virsh start $VM
        # wait until fortivm's restful api is available.
        timeout 120 sh -c 'while ! wget  --no-proxy --no-check-certificate -q -O- http://169.254.254.100; do sleep 0.5; done'
        sleep 60
        ssh -o StrictHostKeyChecking=no -tt admin@169.254.254.100 << 'EOF' > ${LOGDIR}/fgt.log &
config global
diag debug enable
diag debug application httpsd 255
diag debug cli 8
EOF
}

function clean_builtin_fortivm {
    echo "cleaning preexisting fortivm"
    if sudo virsh list --all |grep $VM > /dev/null; then
        sudo virsh destroy $VM || true
        sudo virsh undefine $VM
    fi
    if sudo virsh net-list --all |grep $FGT_MGMT_NET > /dev/null; then
        sudo virsh net-destroy $FGT_MGMT_NET || true
        sudo virsh net-undefine $FGT_MGMT_NET
    fi

    # clean iptable rules
    sudo iptables -D FORWARD -d 169.254.254.100/32 -p tcp -m tcp --dport 443 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -t nat -D PREROUTING -p tcp -m tcp --dport 9443 -j DNAT --to-destination 169.254.254.100:443

    if [[ $PUBLIC_INTERFACE =~ "test" ]]; then
        sudo iptables -D FORWARD -d $FLOATING_RANGE -o $PUBLIC_BRIDGE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        sudo iptables -D FORWARD -s $FLOATING_RANGE -i $PUBLIC_BRIDGE -j ACCEPT
        sudo iptables -D FORWARD -i $PUBLIC_BRIDGE -o $PUBLIC_BRIDGE -j ACCEPT
        sudo iptables -t nat -D POSTROUTING -s $FLOATING_RANGE -d 224.0.0.0/24 -j RETURN
        sudo iptables -t nat -D POSTROUTING -s $FLOATING_RANGE -d 255.255.255.255/32 -j RETURN
        sudo iptables -t nat -D POSTROUTING -s $FLOATING_RANGE ! -d $FLOATING_RANGE -p tcp -j MASQUERADE --to-ports 1024-65535
        sudo iptables -t nat -D POSTROUTING -s $FLOATING_RANGE ! -d $FLOATING_RANGE -p udp -j MASQUERADE --to-ports 1024-65535
        sudo iptables -t nat -D POSTROUTING -s $FLOATING_RANGE ! -d $FLOATING_RANGE -j MASQUERADE
    fi
}


if is_service_enabled fortinet-neutron; then
    if [[ "$1" == "source" ]]; then
        # no-op
        :
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        install_fortigate_neutron_ml2_driver
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        configure_fortigate_neutron_ml2_driver
        if $_use_builtin_vm; then
            configure_builtin_fortivm
        fi
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Add port forwarding for fortivm so GUI can be accessed outside
        if $_use_builtin_vm; then
            sudo iptables -I FORWARD -d 169.254.254.100/32 -p tcp -m tcp --dport 443 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
            sudo iptables -t nat -A PREROUTING -p tcp -m tcp --dport 9443 -j DNAT --to-destination 169.254.254.100:443
        fi
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        if is_service_enabled tempest; then
            configure_tempest_for_fortigate_plugin
        fi
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
        if is_service_enabled q-agt || $_use_builtin_vm; then
            sudo ovs-vsctl --if-exists del-port br-${Q_FORTINET_TENANT_INTERFACE} ${Q_FORTINET_TENANT_INTERFACE}
            sudo ovs-vsctl --if-exists del-br br-${Q_FORTINET_TENANT_INTERFACE}
        fi
        if $_use_builtin_vm; then
            clean_builtin_fortivm
        fi
    fi

    if [[ "$1" == "clean" ]]; then
        # no-op
        :
    fi
fi


$XTRACE
