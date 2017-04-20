======================================
Fortigate plugin for OpenStack Neutron
======================================

1. General
----------

This is an installation guide for enabling Fortigate support on OpenStack.

This guide does not necessarily cover all OpenStack installation steps especially
at production scale.

Please note this instruction only applies to liberty to master version of OpenStack.


2. Prerequisites
----------------
The prerequisites for installing Fortigate pluggin for OpenStack are the
following:

    1. at least 3 machines, physical or vm, with at least 2 core cpu and 4G
       ram, including 1 controller, 1 compute, 1 fortigate.

    2. Controller and compute nodes are installed with Ubuntu 14.04 or CentOS7.

    3. Fortigate is 5.2.3 GA version and up. Clean configuration with only control IP.

    4. 3 virtual switches(ESXI vswitch or linux bridge) or physical switches/vlans:
       1 for control plane, 1 for tenant network, 1 for external network. Vlanids are
       allowed on the switches and enable promisc mode. http and https access are allowed
       on Fortigate’s control interface.

    5. Controller has at least 1 nic on control plane with Internet access.

    6. Compute node has at least 2 nics, one on control plane and the other on tenant
       network.

    7. Fortigate has at least 3 nics, 1 for control plane, 1 for tenant network and 1 for
       external. There should be NO references on the ports for tenant and external network.
       Backup the clean configuration of Fortigate to local machine for later restoration.

3. OpenStack+Fortigate plugin Installation
------------------------------------------

:3.1 Using devstack:

In this scenario, Fortigate plugin will be installed along with OpenStack using devstack

    1. ssh to controller node with sudo privilege and install git.

    2. git clone https://git.openstack.org/openstack-dev/devstack

    3. git clone https://git.openstack.org/openstack/networking-fortinet

    4. cd devstack; sudo tools/create-stack-user.sh if you don’t have a stack user with sudo privilege.

    5. Use ``networking-fortinet/devstack/local.conf.example.controller`` and ``networking-fortinet/devstack/local.conf.example.compute`` as and example to create local.conf for control and compute nodes or use ``networking-fortinet/devstack/local.conf.example.aio`` for all-in-one node and set the required parameters in the local.conf based on the your setup. Items that need to be changed is decorated with CHANGEME.

    6. Run ./stack.sh on controller first and then compute. Remember to get Fortigate ready before running stack.sh.
        

:3.2 On a setup with OpenStack already installed:

In this scenario, Fortigate pluggin will be installed on a setup which has already OpenStack installed:

On the controller node:

1. pip install git+git://git.openstack.org/openstack/networking-fortinet

2. The following modifications are needed in:

  ::

    2.1 /etc/neutron/plugins/ml2/ml2_conf.ini

    [ml2]
    tenant_network_types = vlan
    extension_drivers = port_security
    type_drivers = local,flat,vlan,gre,vxlan
    mechanism_drivers = fortinet,openvswitch

    [ml2_type_vlan]
    network_vlan_ranges = physnet1:1009:2099 ## vlanid range according to your setup

    [ovs]
    bridge_mappings = physnet1:br-eth2 ## the ovs bridge with internal nic for tenant network

    [ml2_fortinet]
    npu_available = True ## if fortigate have hardware npu acceleration, set to True, otherwise, False
    tenant_network_type = vlan
    ext_interface = portx ## port for external traffic
    int_interface = portx ## port for tenant traffic
    password =  ## fortigate admin password
    username = admin ## fortigate admin username
    protocol = https ## if https redirect is enabled(default)
    port = 443 ## if https redirect is enabled(default)
    address = x.x.x.x ## IP address of fortigate control IP, must enable https,http access

    L3 agent  - must be disabled
    DHCP service - must be disabled
    OVS agent - must be enabled

    2.2 neutron.conf:

    [DEFAULT]
    service_plugins = router_fortinet,fwaas_fortinet ## If fortigate is used to provide fwaas, add fwaas_fortinet here.

4. neutron-db-manage --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade head

5. restart neutron server service. service neutron-server restart or systemctl restart neutron-server

6. If you don't have existing configuration, you are done here, but if not, you have existing configuration including networks, subnets, routers, ports and VMs based on tenant network of VLAN type and you want to preserve them, run::

   $ fortinet_migration

7. After the migration, shutdown network node completely if you have a seperate network node. If network node(L3 agent, DHCP agent, Metadata agent) co-exists with controller or compute node, disable L3,DHCP,Metadata agent services and reboot the node.
