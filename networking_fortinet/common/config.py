# Copyright 2015 Fortinet Inc.
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

from neutron.agent.common import config
from oslo_config import cfg

from networking_fortinet.api_client import client

ML2_FORTINET = [
    cfg.StrOpt('address', default='',
               help=_('The address of fortigates to connect to')),
    cfg.StrOpt('port', default='443',
               help=_('The FGT port to serve API requests')),
    cfg.StrOpt('protocol', default='https',
               help=_('The FGT uses which protocol: http or https')),
    cfg.StrOpt('username', default='admin',
               help=_('The username used to login')),
    cfg.StrOpt('password', default='password', secret=True,
               help=_('The password used to login')),
    cfg.StrOpt('int_interface', default='internal',
               help=_('The interface to serve tenant network')),
    cfg.StrOpt('ext_interface', default='',
               help=_('The interface to the external network')),
    cfg.StrOpt('tenant_network_type', default='vlan',
               help=_('tenant network type, default is vlan')),
    cfg.StrOpt('vlink_vlan_id_range', default='3500:4000',
               help=_('vdom link vlan interface, default is 3500:4000')),
    cfg.StrOpt('vlink_ip_range', default='169.254.0.0/20',
               help=_('vdom link interface IP range, '
                     'default is 169.254.0.0/20')),
    cfg.StrOpt('vip_mappedip_range', default='169.254.128.0/23',
               help=_('The intermediate IP range in floating IP process, '
                     'default is 169.254.128.0/23')),
    cfg.BoolOpt('npu_available', default=True,
                help=_('If npu_available is True, it requires hardware FGT'
                      'with NPU, default is True'))
]

cfg.CONF.register_opts(ML2_FORTINET, "ml2_fortinet")
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)

fgt_info = {
    'address': cfg.CONF.ml2_fortinet.address,
    'port': cfg.CONF.ml2_fortinet.port,
    'protocol': cfg.CONF.ml2_fortinet.protocol,
    'username': cfg.CONF.ml2_fortinet.username,
    'password': cfg.CONF.ml2_fortinet.password,
    'int_interface': cfg.CONF.ml2_fortinet.int_interface,
    'ext_interface': cfg.CONF.ml2_fortinet.ext_interface,
    'tenant_network_type': cfg.CONF.ml2_fortinet.tenant_network_type,
    'vlink_vlan_id_range': cfg.CONF.ml2_fortinet.vlink_vlan_id_range,
    'vlink_ip_range': cfg.CONF.ml2_fortinet.vlink_ip_range,
    'vip_mappedip_range': cfg.CONF.ml2_fortinet.vip_mappedip_range,
    'npu_available': cfg.CONF.ml2_fortinet.npu_available
}


def get_apiclient():
    """Fortinet api client initialization."""
    api_server = [(fgt_info['address'], fgt_info['port'],
                  'https' == fgt_info['protocol'])]
    return client.FortiosApiClient(
        api_server, fgt_info['username'], fgt_info['password'])
