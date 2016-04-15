#!/bin/bash
if [[ ! $1 || ! $2 ]]; then
    echo "usage: ./demo.sh action tenant_name"
    echo "action: add-tenant, create-tenant-net, create-public-net, boot-vm"
    exit 1
fi
source openrc admin admin
PROJECT_NAME=$2
INT_NET=${PROJECT_NAME}_private
INT_CIDR=10.101.0.0/24
INT_SUBNET=${PROJECT_NAME}_subnet
TENANT_ROUTER=${PROJECT_NAME}_router
FLOAT_START=10.0.20.100
FLOAT_END=10.0.20.150
FLOAT_GW=10.0.20.1
FLOAT_CIDR=10.0.20.0/24
IMAGE_ID=cirros-0.3.4-x86_64-uec
case "$1" in
add-tenant)  openstack project create $PROJECT_NAME
             openstack role add --user admin --project $PROJECT_NAME admin
             nova --os-project-name $PROJECT_NAME secgroup-add-rule default udp 1 65535 0.0.0.0/0
             nova --os-project-name $PROJECT_NAME secgroup-add-rule default tcp 22 22 0.0.0.0/0
             nova --os-project-name $PROJECT_NAME secgroup-add-rule default icmp -1 -1 0.0.0.0/0
                ;;
create-tenant-net) neutron --os-project-name $PROJECT_NAME net-create $INT_NET
                 neutron --os-project-name $PROJECT_NAME subnet-create --name $INT_SUBNET $INT_NET $INT_CIDR
                 neutron --os-project-name $PROJECT_NAME router-create $TENANT_ROUTER
                 neutron --os-project-name $PROJECT_NAME router-gateway-set $TENANT_ROUTER public
                 neutron router-interface-add $TENANT_ROUTER $INT_SUBNET
                 ;;
create-public-net) publicnetid=`neutron net-show public|grep " id "|awk '{print$4}'` 2>&1 >/dev/null
                   if [[ -z $publicnetid ]]; then
                       neutron net-create public -- --router:external=True
                       neutron subnet-create --allocation-pool start=$FLOAT_START,end=$FLOAT_END \
                       --gateway $FLOAT_GW --name public_subnet public $FLOAT_CIDR -- --enable-dhcp False
                   fi
                   ;;
boot-vm) export portid=`neutron --os-project-name $PROJECT_NAME port-create $INT_NET \
         |grep " id " |awk '{print$4}'`
         neutron --os-project-name $PROJECT_NAME floatingip-create --port-id $portid public 
         nova --os-project-name $PROJECT_NAME boot --flavor m1.tiny --image $IMAGE_ID \
         --nic port-id=$portid test1
         ;;
*) echo "Action $1 is not processed"
   ;;
esac
