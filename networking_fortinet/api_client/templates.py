# Copyright (c) 2015 Fortinet, Inc.
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

#    FortiOS API request format templates.

# About api request message naming regulations:
# Prefix         HTTP method
# ADD_XXX    -->    POST
# SET_XXX    -->    PUT
# DELETE_XXX -->    DELETE
# GET_XXX    -->    GET

# Login
LOGIN = """
{
    "path": "/logincheck",
    "method": "POST",
    "body": {
        "username": "{{ username }}",
        "secretkey": "{{ secretkey }}"
    }
}
"""

RELOGIN = """login?redir=%2fapi%2fv2"""

LOGOUT = """
{
    "path": "/logout",
    "method": "POST"
}
"""

# Create VLAN
ADD_VLAN_INTERFACE = """
{
    "path": "/api/v2/cmdb/system/interface/",
    "method": "POST",
    "body": {
        "name": "interface",
        "json": {
            {% if name is defined %}
                "name": "{{ name }}",
            {% else %}
                "name": "os_vid_{{ vlanid }}",
            {% endif %}
            {% if vlanid is defined %}
                "vlanid": "{{ vlanid }}",
            {% endif %}
            "interface": "{{ interface }}",
            "vdom": "{{ vdom }}",
            "type": "vlan",
            {% if ip is defined %}
                "ip": "{{ ip }}",
                "mode": "static",
                "allowaccess": "ping",
            {% endif %}
            "secondary-IP":"enable",
            {% if alias is defined %}
                "alias": "{{ alias  }}",
            {% endif %}
            "ipv6": {
                "ip6-extra-addr": []
            }
        }
    }
}
"""

SET_VLAN_INTERFACE = """
{
    "path": "/api/v2/cmdb/system/interface/{{ name }}",
    "method": "PUT",
    "body": {
        "json": {
            {% if ip is defined and ip != None %}
                "ip": "{{ ip }}",
                "mode": "static",
                "allowaccess": "ping",
            {% endif %}
            {% if secondaryips is defined %}
                {% if secondaryips %}
                    "secondary-IP": "enable",
                    "secondaryip": [
                    {% for secondaryip in secondaryips[:-1] %}
                        {
                            "ip": "{{ secondaryip }}",
                            "allowaccess": "ping"
                        },
                    {% endfor %}
                        {
                            "ip": "{{ secondaryips[-1] }}",
                            "allowaccess": "ping"
                        }
                    ],
                {% else %}
                    "secondary-IP": "disable",
                {% endif %}
            {% endif %}
            {% if vlanid is defined %}
                "vlanid": "{{ vlanid }}",
            {% endif %}
            {% if vdom is defined %}
                "vdom": "{{ vdom }}"
            {% else %}
                "vdom": "root"
            {% endif %}
        }
    }
}
"""

# Delete VLAN (vlan id)
DELETE_VLAN_INTERFACE = """
{
    "path": "/api/v2/cmdb/system/interface/{{ name }}",
    "method": "DELETE",
    "body": {
        "name": "interface",
        "json": {
            {% if vdom is defined %}
                "vdom": "{{ vdom }}"
            {% else %}
                "vdom": "root"
            {% endif %}
        }
    }
}
"""

# Get VLAN interface info
GET_VLAN_INTERFACE = """
{
    {% if name is defined %}
        {% if vdom is defined %}
        "path":"/api/v2/cmdb/system/interface/{{ name }}/?vdom={{ vdom }}",
        {% else %}
        "path":"/api/v2/cmdb/system/interface/{{ name }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path":"/api/v2/cmdb/system/interface/?vdom={{ vdom }}",
        {% else %}
            "path":"/api/v2/cmdb/system/interface/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""


ADD_DHCP_SERVER = """
{
    "path":"/api/v2/cmdb/system.dhcp/server/",
    "method": "POST",
    "body": {
        "name": "server",
        {% if vdom is defined %}
        "vdom": "{{ vdom }}",
        {% endif %}
        "json": {
            "status":"enable",
            {% if dns_nameservers is defined and dns_nameservers %}
            "dns-service":"specify",
            {% for dns in dns_nameservers[:3] %}
            "dns-server{{ loop.index }}":"{{ dns }}",
            {% endfor %}
            {% else %}
            "dns-service":"default",
            {% endif %}
            {% if gateway != None %}
            "default-gateway":"{{ gateway }}",
            {% endif %}
            "netmask":"{{ netmask }}",
            "interface":"{{ interface }}",
            "ip-range":[
                {
                    "start-ip":"{{ start_ip }}",
                    "end-ip":"{{ end_ip }}"
                }
            ]
        }
    }
}
"""

SET_DHCP_SERVER = """
{
    "path":"/api/v2/cmdb/system.dhcp/server/{{ id }}/",
    "method": "PUT",
    "body": {
        "name": "server",
        {% if vdom is defined %}
        "vdom": "{{ vdom }}",
        {% endif %}
        "json": {
            "status":"enable",
            {% if dns_nameservers is defined and dns_nameservers %}
            "dns-service":"specify",
            {% for dns in dns_nameservers[:3] %}
            "dns-server{{ loop.index }}":"{{ dns }}",
            {% endfor %}
            {% else %}
            "dns-service":"default",
            {% endif %}
            {% if gateway != None %}
            "default-gateway":"{{ gateway }}",
            {% endif %}
            "netmask":"{{ netmask }}",
            "interface":"{{ interface }}",
            "ip-range":[
                {
                    "start-ip":"{{ start_ip }}",
                    "end-ip":"{{ end_ip }}"
                }
            ]
        }
    }
}
"""


DELETE_DHCP_SERVER = """
{
    "path":"/api/v2/cmdb/system.dhcp/server/{{ id }}/",
    "method": "DELETE",
    "body": {
        "name": "server",
        {% if vdom is defined %}
        "vdom": "{{ vdom }}",
        {% endif %}
        "id": "{{ id }}",
        "json": {
        }
    }
}
"""

GET_DHCP_SERVER = """
{
    {% if id is defined %}
        {% if vdom is defined %}
            "path":"/api/v2/cmdb/system.dhcp/server/{{ id }}/?vdom={{ vdom }}",
        {% else %}
            "path":"/api/v2/cmdb/system.dhcp/server/{{ id }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path":"/api/v2/cmdb/system.dhcp/server/?vdom={{ vdom }}",
        {% else %}
            "path":"/api/v2/cmdb/system.dhcp/server/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""


SET_DHCP_SERVER_RSV_ADDR = """
{
    "path":"/api/v2/cmdb/system.dhcp/server/{{ id }}/reserved-address",
    "method": "PUT",
    "body": {
        {% if vdom is defined %}
        "vdom": "{{ vdom }}",
        {% endif %}
        "json": {
            "reserved-address": {{ reserved_address }}
        }
    }
}
"""


ADD_VDOM = """
{
    "path":"/api/v2/cmdb/system/vdom/",
    "method": "POST",
    "body": {
        "name": "vdom",
        "json": {
            "name":"{{ name }}"
        }
    }
}
"""

DELETE_VDOM = """
{
    "path":"/api/v2/cmdb/system/vdom/{{ name }}",
    "method": "DELETE",
    "body": {
    }
}
"""

GET_VDOM = """
{
    "path":"/api/v2/cmdb/system/vdom/{{ name }}",
    "method": "GET"
}
"""

ADD_VDOM_LINK = """
{
    "path":"/api/v2/cmdb/system/vdom-link/",
    "method": "POST",
    "body": {
        "name": "vdom-link",
        "json": {
            "name":"{{ name }}"
        }
    }
}
"""

DELETE_VDOM_LINK = """
{
    "path": "/api/v2/cmdb/system/vdom-link/{{ name }}",
    "method": "DELETE",
    "body": {
    }
}
"""

GET_VDOM_LINK = """
{
    "path":"/api/v2/cmdb/system/vdom-link/{{ name }}",
    "method": "GET"
}
"""


ADD_VDOM_LNK_INTERFACE = """
{
    "path":"/api/v2/cmdb/system/interface/",
    "method": "POST",
    "body": {
        "name": "vdom-link",
        "json": {
            "name":"{{ name }}"
        }
    }
}
"""


ADD_ROUTER_STATIC = """
{
    "path": "/api/v2/cmdb/router/static/",
    "method": "POST",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "json": {
            "dst": "{{ dst }}",
            "device": "{{ device }}",
            "gateway": "{{gateway }}"
        }
    }
}
"""

SET_ROUTER_STATIC = """
{
    "path": "/api/v2/cmdb/router/static/{{ id }}/",
    "method": "PUT",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "json": {
            "dst": "{{ dst }}",
            "device": "{{ device }}",
            "gateway": "{{gateway }}"
        }
    }
}
"""


DELETE_ROUTER_STATIC = """
{
    "path": "/api/v2/cmdb/router/static/{{ id }}/",
    "method": "DELETE",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "json": {
        }
    }
}
"""


GET_ROUTER_STATIC = """
{
    {% if id is defined %}
        {% if vdom is defined %}
            "path":"/api/v2/cmdb/router/static/{{ id }}/?vdom={{ vdom }}",
        {% else %}
            "path":"/api/v2/cmdb/router/static/{{ id }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path":"/api/v2/cmdb/router/static/?vdom={{ vdom }}",
        {% else %}
            "path":"/api/v2/cmdb/router/static/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""


ADD_FIREWALL_POLICY = """
{
    "path": "/api/v2/cmdb/firewall/policy/",
    "method": "POST",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "json": {
            "srcintf": [
                {
                    {% if srcintf is defined %}
                        "name": "{{ srcintf }}"
                    {% else %}
                        "name": "any"
                    {% endif %}
                }
            ],
            "dstintf": [
                {
                    {% if dstintf is defined %}
                        "name": "{{ dstintf }}"
                    {% else %}
                        "name": "any"
                    {% endif %}
                }
            ],
            "srcaddr":  [
                {
                    {% if srcaddr is defined %}
                        "name": "{{ srcaddr }}"
                    {% else %}
                        "name": "all"
                    {% endif %}
                }
            ],
            "dstaddr":  [
                {
                    {% if dstaddr is defined %}
                        "name": "{{ dstaddr }}"
                    {% else %}
                        "name": "all"
                    {% endif %}
                }
            ],
            {% if action is defined %}
                "action": "{{ action }}",
            {% else %}
                "action": "accept",
            {% endif %}
            "schedule": "always",
            {% if nat is defined %}
            "nat": "{{ nat }}",
            {% endif %}
            {% if poolname is defined %}
                {% if nat is not defined %}
                    "nat": "enable",
                {% endif %}
                "ippool": "enable",
                "poolname":[{
                    "name": "{{ poolname }}"
                }],
            {% endif %}
            {% if match_vip is defined %}
                "match-vip": "{{ match_vip }}",
            {% else %}
                "match-vip": "disable",
            {% endif %}
            {% if status is defined %}
                "status": "{{ status }}",
            {% else %}
                "status": "enable",
            {% endif %}
            "service":  [{
                {% if service is defined %}
                    "name": "{{ service }}"
                {% else %}
                    "name": "ALL"
                {% endif %}
            }],
            {% set profiles = {
                'av-profile': av_profile,
                'webfilter-profile': webfilter_profile,
                'ips-sensor': ips_sensor,
                'application-list': application_list,
                'ssl-ssh-profile': ssl_ssh_profile
            } %}
            {% set _utm_enable = true %}
            {% for k, v in profiles.iteritems() if v is defined and v %}
               {% if _utm_enable %}
                   {%set _utm_enable = false %}
                   "utm-status": "enable",
                   "profile-protocol-options":"default",
               {% endif %}
               "{{ k }}": "{{ v }}",
            {% else %}
               "utm-status": "disable",
               "profile-protocol-options": "",
            {% endfor %}
            {% if comments is defined %}
                "comments": "{{ comments }}"
            {% else %}
                "comments": ""
            {% endif %}
        }
    }
}
"""

SET_FIREWALL_POLICY = """
{
    "path": "/api/v2/cmdb/firewall/policy/{{ id }}/",
    "method": "PUT",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "json": {
            {% if srcintf is defined %}
                "srcintf": [
                    {
                        "name": "{{ srcintf }}"
                    }
                ],
            {% endif %}
            {% if dstintf is defined %}
                "dstintf": [
                    {
                        "name": "{{ dstintf }}"
                    }
                ],
            {% endif %}
            {% if srcaddr is defined %}
                "srcaddr":  [
                    {
                        "name": "{{ srcaddr }}"
                    }
                ],
            {% endif %}
            {% if dstaddr is defined %}
                "dstaddr":  [
                    {
                        "name": "{{ dstaddr }}"
                    }
                ],
            {% endif %}
            {% if action is defined %}
                "action": "{{ action }}",
            {% endif %}
            {% if nat is defined %}
            "nat": "{{ nat }}",
            {% endif %}
            {% if poolname is defined %}
                {% if nat is not defined %}
                    "nat": "enable",
                {% endif %}
                "ippool": "enable",
                "poolname":[{
                    "name":"{{ poolname }}"
                }],
            {% endif %}
            {% if match_vip is defined %}
                "match-vip":"{{ match_vip }}",
            {% endif %}
            {% if status is defined %}
                "status":"{{ status }}",
            {% endif %}
            {% if service is defined %}
                "service":  [{
                    "name": "{{ service }}"
                }],
            {% endif %}
            {% set profiles = {
                'av-profile': av_profile,
                'webfilter-profile': webfilter_profile,
                'ips-sensor': ips_sensor,
                'application-list': application_list,
                'ssl-ssh-profile': ssl_ssh_profile
            } %}
            {% set _utm_enable = true %}
            {% for k, v in profiles.iteritems() if v is defined and v is not none %}
               {% if _utm_enable %}
                   {%set _utm_enable = false %}
                   "utm-status": "enable",
                   "profile-protocol-options":"default",
               {% endif %}
               "{{ k }}": "{{ v }}",
            {% else %}
               "utm-status": "disable",
               "profile-protocol-options": "",
            {% endfor %}
            {% if comments is defined %}
                "comments": "{{ comments }}",
            {% endif %}
            "schedule": "always"
        }
    }
}
"""

DELETE_FIREWALL_POLICY = """
{
    "path": "/api/v2/cmdb/firewall/policy/{{ id }}/",
    "method": "DELETE",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "json": {
        }
    }
}
"""

GET_FIREWALL_POLICY = """
{
    {% if id is defined %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/policy/{{ id }}/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/policy/{{ id }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/policy/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/policy/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""


MOVE_FIREWALL_POLICY = """
{
    "path": "/api/v2/cmdb/firewall/policy/{{ id }}",
    "method": "PUT",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        {% if before is defined %}
            "before": "{{ before }}",
        {% else %}
            "after": "{{ after }}",
        {% endif %}
        "action": "move"
    }
}
"""


ADD_FIREWALL_VIP = """
{
    "path":"/api/v2/cmdb/firewall/vip/",
    "method": "POST",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "vip",
        "json": {
            "name": "{{ name }}",
            "extip": "{{ extip }}",
            "extintf": "{{ extintf }}",
            "mappedip": [{
                    "range": "{{ mappedip }}"
            }]
        }
    }
}
"""

DELETE_FIREWALL_VIP = """
{
    "path":"/api/v2/cmdb/firewall/vip/{{ name }}",
    "method": "DELETE",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "vip"
    }
}
"""

GET_FIREWALL_VIP = """
{
    {% if name is defined %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/vip/{{ name }}/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/vip/{{ name }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/vip/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/vip/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""

ADD_FIREWALL_IPPOOL = """
{
    "path":"/api/v2/cmdb/firewall/ippool/",
    "method": "POST",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "ippool",
        "json": {
            "startip": "{{ startip }}",
            {% if endip is defined %}
                "endip": "{{ endip }}",
            {% else %}
                "endip": "{{ startip }}",
            {% endif %}
            {% if type is defined %}
                "type": "{{ type }}",
            {% else %}
                "type": "one-to-one",
            {% endif %}
            {% if comments is defined %}
                "comments": "{{ comments }}",
            {% endif %}
            {% if name is defined %}
                "name": "{{ name }}"
            {% else %}
                "name": "{{ startip }}"
            {% endif %}
        }
    }
}
"""

DELETE_FIREWALL_IPPOOL = """
{
    "path":"/api/v2/cmdb/firewall/ippool/{{ name }}",
    "method": "DELETE",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "ippool"
    }
}
"""

GET_FIREWALL_IPPOOL = """
{
    {% if name is defined %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/ippool/{{ name }}/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/ippool/{{ name }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/ippool/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/ippool/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""

## firewall addresses
ADD_FIREWALL_ADDRESS = """
{
    "path":"/api/v2/cmdb/firewall/address/",
    "method": "POST",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "address",
        "json": {
            {% if associated_interface is defined %}
                "associated-interface": "{{ associated_interface }}",
            {% endif %}
            {% if comment is defined %}
                "comment": "{{ comment }}",
            {% endif %}
            "subnet": "{{ subnet }}",
            "name": "{{ name }}"
        }
    }
}
"""

SET_FIREWALL_ADDRESS = """
{
    "path":"/api/v2/cmdb/firewall/address/{{ name }}",
    "method": "PUT",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "address",
        "json": {
            {% if associated_interface is defined %}
                "associated-interface": "{{ associated_interface }}",
            {% endif %}
            {% if comment is defined %}
                "comment": "{{ comment }}",
            {% endif %}
            {% if subnet is defined %}
                "subnet": "{{ subnet }}",
            {% endif %}
            "name": "{{ name }}"
        }
    }
}
"""

DELETE_FIREWALL_ADDRESS = """
{
    "path":"/api/v2/cmdb/firewall/address/{{ name }}",
    "method": "DELETE",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "address"
    }
}
"""

GET_FIREWALL_ADDRESS = """
{
    {% if name is defined %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/address/{{ name }}/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/address/{{ name }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/address/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/address/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""

## firewall address group
ADD_FIREWALL_ADDRGRP = """
{
    "path":"/api/v2/cmdb/firewall/addrgrp/",
    "method": "POST",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "addrgrp",
        "json": {
            "name": "{{ name }}",
            "member": [
            {% for member in members[:-1] %}
                {
                    "name": "{{ member }}"
                },
            {% endfor %}
                {
                    "name": "{{ members[-1] }}"
                }
            ]
        }
    }
}
"""

SET_FIREWALL_ADDRGRP = """
{
    "path": "/api/v2/cmdb/firewall/addrgrp/{{ name }}/",
    "method": "PUT",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "json": {
            "member": [
            {% for member in members[:-1] %}
                {
                    "name": "{{ member }}"
                },
            {% endfor %}
                {
                    "name": "{{ members[-1] }}"
                }
            ]
        }
    }
}
"""


DELETE_FIREWALL_ADDRGRP = """
{
    "path":"/api/v2/cmdb/firewall/addrgrp/{{ name }}",
    "method": "DELETE",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "addrgrp"
    }
}
"""

GET_FIREWALL_ADDRGRP = """
{
    {% if vdom is defined %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/addrgrp/{{ name }}/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/addrgrp/{{ name }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall/addrgrp/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall/addrgrp/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""

## firewall service custom
ADD_FIREWALL_SERVICE = """
{
    "path": "/api/v2/cmdb/firewall.service/custom/",
    "method": "POST",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "custom",
        "json": {
            {% if protocol is defined %}
                "protocol": "{{ protocol }}",
            {% else %}
                "protocol": "TCP/UDP/SCTP",
            {% endif %}
            {% if fqdn is defined %}
                "fqdn": "{{ fqdn }}",
            {% endif %}
            {% if iprange is defined %}
                "iprange": "{{ iprange }}",
            {% endif %}
            {% if tcp_portrange is defined %}
                "tcp-portrange": "{{ tcp_portrange }}",
            {% endif %}
            {% if udp_portrange is defined %}
                "udp-portrange": "{{ udp_portrange }}",
            {% endif %}
            {% if sctp_portrange is defined %}
                "sctp-portrange": "{{ udp_portrange }}",
            {% endif %}
            {% if comment is defined %}
                "comment": "{{ comment }}",
            {% endif %}
            "name": "{{ name }}"
        }
    }
}
"""

## update firewall service custom
SET_FIREWALL_SERVICE = """
{
    "path": "/api/v2/cmdb/firewall.service/custom/{{ name }}",
    "method": "PUT",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "custom",
        "json": {
            {% if protocol is defined %}
                "protocol": "{{ protocol }}",
            {% endif %}
            {% if fqdn is defined %}
                "fqdn": "{{ fqdn }}",
            {% endif %}
            {% if iprange is defined %}
                "iprange": "{{ iprange }}",
            {% endif %}
            {% if tcp_portrange is defined %}
                "tcp-portrange": "{{ tcp_portrange }}",
            {% else %}
                "tcp-portrange": "",
            {% endif %}
            {% if udp_portrange is defined %}
                "udp-portrange": "{{ udp_portrange }}",
            {% else %}
                "udp-portrange": "",
            {% endif %}
            {% if sctp_portrange is defined %}
                "sctp-portrange": "{{ sctp_portrange }}",
            {% else %}
                "sctp-portrange": "",
            {% endif %}
            {% if comment is defined %}
                "comment": "{{ comment }}",
            {% endif %}
            "name": "{{ name }}"
        }
    }
}
"""

DELETE_FIREWALL_SERVICE = """
{
    "path":"/api/v2/cmdb/firewall.service/custom/{{ name }}",
    "method": "DELETE",
    "body": {
        {% if vdom is defined %}
            "vdom": "{{ vdom }}",
        {% else %}
            "vdom": "root",
        {% endif %}
        "name": "custom"
    }
}
"""

GET_FIREWALL_SERVICE = """
{
    {% if name is defined %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall.service/custom/{{ name }}/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall.service/custom/{{ name }}/",
        {% endif %}
    {% else %}
        {% if vdom is defined %}
            "path": "/api/v2/cmdb/firewall.service/custom/?vdom={{ vdom }}",
        {% else %}
            "path": "/api/v2/cmdb/firewall.service/custom/",
        {% endif %}
    {% endif %}
    "method": "GET"
}
"""