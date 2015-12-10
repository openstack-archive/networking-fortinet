# Copyright (c) 2015 Fortinet Inc.
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

import requests

from oslo_config import cfg

from neutron.tests import base


OK = requests.codes.ok

FGT_HOST = 'fake_host'
FGT_USR = 'admin'
FGT_PWD = ''
FGT_INT_INF = 'port2'
FGT_EXT_INF = 'port3'
FGT_NPU = False

TEST_TENANT = 'test123'
TEST_NETNAME = 'net_test123'
TEST_NETWORK = 'net_test123'
TEST_SUBNET = '4.3.2.1/24'

FGT_VLANID_FROM = 1009
FGT_VLANID_TO = 1099

TEST_ROUTER = 'router_id'


class ConfigMixin(object):

    """Mock the config for Fortinet driver and service unit tests."""

    def __init__(self):
        self.mocked_parser = None

    def set_up_mocks(self):
        # Mock the configuration file
        base.BaseTestCase.config_parse()

        cfg.CONF.set_override('service_plugins', 'router_fortinet')

        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['fortinet', 'openvswitch'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
            cfg.CONF.import_opt(opt, 'neutron.plugins.ml2.config', 'ml2')
            cfg.CONF.set_override(opt, val, 'ml2')

        # Configure the ML2 type_vlan opts
        cfg.CONF.import_opt('network_vlan_ranges',
                           'neutron.plugins.ml2.drivers.type_vlan',
                           group='ml2_type_vlan')

        ml2_type_vlan_opts = {
            'vlan_ranges': ['physnet1:1000:1099'],
        }
        cfg.CONF.set_override('network_vlan_ranges',
                              ml2_type_vlan_opts['vlan_ranges'],
                              'ml2_type_vlan')
        self.vlan_ranges = ml2_type_vlan_opts['vlan_ranges']

        # Configure the Fortinet mechanism driver
        fgt_test_config = {
            'address': FGT_HOST,
            'username': FGT_USR,
            'password': FGT_PWD,
            'npu_available': FGT_NPU,
            'ext_interface': FGT_EXT_INF,
            'int_interface': FGT_INT_INF
        }
        for opt, val in fgt_test_config.items():
            cfg.CONF.set_override(opt, val, 'ml2_fortinet')
        self._fortigate = cfg.CONF.ml2_fortinet


class FakeDbContract(object):

    def __init__(self, contract_id):
        self.contract_id = contract_id
