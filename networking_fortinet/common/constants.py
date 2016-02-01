# # Copyright 2015 Fortinet Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import netaddr

PREFIX = {
    'vdom': 'osvdm',
    'inf': 'os_vid_',
    'vint': '_0',
    'vext': '_1',
    'vdlink': '_',
    'addrgrp': 'addrgrp_',
    'source_ip_address': 'src_',
    'destination_ip_address': 'dst_'
}

POSTFIX = {
    'vint': '_0',
    'vext': '_1',
    'vdlink': '_',
    'fip': '+'
}

# TYPE
TYPE_EXT = 'ext2int'
TYPE_INT = 'int2int'
TYPE_FIP = 'ext2fip'

#EXT_VDOM = 'root'
EXT_VDOM = 'osvdmext'
EXT_DEF_DST = '0.0.0.0 0.0.0.0'
DEF_GW = '0.0.0.0'
FIELD_DELIMITER = ':'
INIT_TASK_ID = 'init_task_id'
FAKE_TENANT_ID = '__fake_tenant_id_for_default_vdom'
FORTINET_PARAMS = {
    'vlink_vlan_id_range': {
        'cls': 'Fortinet_Vlink_Vlan_Allocation',
        'type': int,
        'format': True,
        'range': range,
        'keys': ('vlanid',)
    },
    'vlink_ip_range': {
        'cls': 'Fortinet_Vlink_IP_Allocation',
        'type': netaddr.IPNetwork,
        'format': False,
        'range': netaddr.IPNetwork.subnet,
        'keys': ('vlink_ip_subnet',),
        'netmask': 30
    },
    'vip_mappedip_range': {
        'cls': 'Fortinet_FloatingIP_Allocation',
        'type': netaddr.IPNetwork,
        'format': False,
        'range': netaddr.IPNetwork.subnet,
        'keys': ('ip_subnet',),
        'netmask': 32
    }
}


# Define class
FORTINET_MAPS = {
    'vdom_link': {
        'api': {
            'get': 'GET_VDOM_LNK',
        },
        'cls': 'Fortinet_Vlink_Vlan_Allocation',
        'type': int,
        'format': True,
        'range': range,
        'keys': ('vlanid',)
    },
    'vlink_ip_range': {
        'cls': 'Fortinet_Vlink_IP_Allocation',
        'type': netaddr.IPNetwork,
        'format': False,
        'range': netaddr.IPNetwork.subnet,
        'keys': ('vlink_ip_subnet',)
    }
}
