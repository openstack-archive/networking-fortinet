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

import mock
from neutron.tests import base
from oslo_config import cfg
from oslo_db.sqlalchemy import session
import six

from networking_fortinet.ml2 import mech_fortinet
from networking_fortinet.tests.unit import (
    test_fortinet_common as mocked)

TEST_SEG1 = 'seg1'

SUPPORTED_DR = ['vlan']


class TestFortinetMechDriver(base.BaseTestCase,
                             mocked.ConfigMixin):

    def setUp(self):
        super(TestFortinetMechDriver, self).setUp()
        mocked.ConfigMixin.set_up_mocks(self)
        self.driver = mech_fortinet.FortinetMechanismDriver()
        self.driver.sync_conf_to_db = mock.Mock()
        self.driver.sync_conf_to_db.return_value = 'ok'
        self.patcher1 = mock.patch(
            'networking_fortinet.db.models.Fortinet_ML2_Namespace')
        self.patcher2 = mock.patch(
            'networking_fortinet.common.resources.Vdom')
        self.patcher3 = mock.patch(
            'networking_fortinet.db.models.Fortinet_Interface')
        self.addCleanup(self.patcher1.stop)
        self.mock_db_namespace = self.patcher1.start()
        self.addCleanup(self.patcher2.stop)
        self.mock_res_vdom = self.patcher2.start()
        self.addCleanup(self.patcher3.stop)
        self.mock_db_inf = self.patcher3.start()

    def test_initialize(self):
        self.driver.initialize()

    def _setup_network_context(self):
        net = {
            'name': 'test',
            'tenant_id': 'test',
            'provider: network_type': '',
            'router:external': False,
            'id': '123',
            'provider:segmentation_id': 0
        }

        segment = {
            'segmentation_id': 0,
            'physical_network': 'physnet1',
            'id': '123',
            'network_type': 'vlan'
        }
        context = Fake_context()
        mech_context = Fake_mech_context(_plugin_context=context,
                                         current=net,
                                         network_segments=[segment])
        return mech_context

    def _setup_subnet_context(self):
        subnet = {
            'allocation_pools': [{
                'start': '172.20.21.2',
                'end': '172.20.21.254'
            }],
            'cidr': '172.20.21.0/24',
            'id': 'ee1506dc-d1a9-45b3-840e-137bdaebce52',
            'enable_dhcp': True,
            'network_id': u'ad47f7b8-4bb7-4591-b8ed-f720237dd24f',
            'tenant_id': u'11513667f4ee4a14acb0985659456f24',
            'dns_nameservers': [],
            'gateway_ip': u'172.20.21.1',
            'shared': False
        }
        context = Fake_context()
        mech_context = Fake_mech_context(_plugin_context=context,
                                         current=subnet)
        return mech_context

    def _setup_port_context(self):
        port = {
                'device_owner': 'network:router_interface',
                'fixed_ips': [{
                    'subnet_id': u'f645b09c-a34a-42fb-9c14-b999e43a54c7',
                    'ip_address': u'172.20.21.1'
                }],
                'id': 'fb66def6-bd5e-44a0-a3f7-7c0e8e08d9ff',
                'device_id': u'e4020c65-7003-468b-a34d-31af297397a0',
                'admin_state_up': True,
                'network_id': u'f8e34426-ccf7-429c-b726-3809d54cabdc',
                'tenant_id': u'11513667f4ee4a14acb0985659456f24',
                'mac_address': u'00: 0c: 29: d9: 18: 3f'
               }
        context = Fake_context()
        mech_context = Fake_mech_context(_plugin_context=context,
                                         current=port)
        return mech_context

    @mock.patch('networking_fortinet.common.resources.VlanInterface')
    def test_create_network_postcommit(self, VlanInterface):
        self.driver.initialize()
#        query_inf_db_none = mock.Mock(return_value=None)
#        self.inf_db.query = query_inf_db_none
#        add_inf_db_ok = mock.Mock(return_value='cool')
#        self.inf_db.add_record = add_inf_db_ok
#        self.inf_res = VlanInterface()
#        get_inf_res_ok = mock.Mock(return_value='cool')
#        get_inf_res_404 = mock.Mock(side_effect=exception.ResourceNotFound)
#        add_inf_res_ok = mock.Mock(return_value='cool')
        mech_context = self._setup_network_context()
#        self.inf_res.get = get_inf_res_ok
#        self.driver.create_network_postcommit(mech_context)
#        self.inf_res.get = get_inf_res_404
        #print self.inf_res.get('dfafa')
#        self.inf_res.add = add_inf_res_ok
        self.driver.create_network_postcommit(mech_context)
#        print self.inf_db.add_record.called
#        self.assertTrue(self.namespace_db.add_record.called)

    @mock.patch('networking_fortinet.common.resources.VlanInterface')
    def test_delete_network_precommit(self, VlanInterface):
        self.driver.initialize()
        mech_context = self._setup_network_context()
        namespace = mock.Mock()
        namespace.vdom = 'osvdm123'
        with mock.patch('networking_fortinet.db.models.query_record',
                        side_effect=[None, namespace, 'fgt_intf']):
            self.driver.delete_network_precommit(mech_context)

    @mock.patch('networking_fortinet.common.resources.VlanInterface')
    @mock.patch('networking_fortinet.db.models.Fortinet_Vdom_Vlink')
    @mock.patch('networking_fortinet.db.models.Fortinet_Vlink_Vlan_Allocation')
    @mock.patch('networking_fortinet.db.models.Fortinet_Vlink_IP_Allocation')
    @mock.patch('networking_fortinet.db.models.Fortinet_Static_Router')
    @mock.patch('networking_fortinet.common.resources.RouterStatic')
    @mock.patch('networking_fortinet.common.resources.VdomLink')
    def test_delete_network_postcommit(self, VlanInterface,
                                       Fortinet_Vdom_Vlink,
                                       Fortinet_Vlink_Vlan_Allocation,
                                       Fortinet_Vlink_IP_Allocation,
                                       Fortinet_Static_Router,
                                       RouterStatic,
                                       VdomLink):
        self.driver.initialize()
        mech_context = self._setup_network_context()
        namespace = mock.Mock()
        namespace.tenant_id = mech_context.current['tenant_id']
        with mock.patch('networking_fortinet.db.models.query_count',
                        return_value=0):
            with mock.patch('networking_fortinet.db.models.query_record',
                            return_value=namespace):
                    with mock.patch(
                             'networking_fortinet.db.models.query_records',
                             return_value='cool'):
                        self.driver.delete_network_postcommit(mech_context)

    @mock.patch('networking_fortinet.db.models.Fortinet_Static_Router')
    @mock.patch('networking_fortinet.common.resources.RouterStatic')
    @mock.patch('networking_fortinet.db.models.Fortinet_ML2_Subnet')
    @mock.patch('networking_fortinet.common.resources.DhcpServer')
    @mock.patch('networking_fortinet.common.resources.VlanInterface')
    def test_create_subnet_postcommit(self, Fortinet_Static_Router,
                                      RouterStatic,
                                      Fortinet_ML2_Subnet, DhcpServer,
                                      VlanInterface):
        self.driver.initialize()
        mech_context = self._setup_subnet_context()
        namespace = mock.Mock()
        namespace.vdom = 'osvdm123'
        with mock.patch('networking_fortinet.db.models.query_record',
                        return_value='external network'):
            self.driver.create_subnet_postcommit(mech_context)
        with mock.patch('networking_fortinet.db.models.query_record',
                        side_effect=[None, namespace, 101, 'fortinet_inf']):
            self.driver.create_subnet_postcommit(mech_context)

    @mock.patch('networking_fortinet.db.models.Fortinet_Static_Router')
    @mock.patch('networking_fortinet.common.resources.RouterStatic')
    @mock.patch('networking_fortinet.db.models.Fortinet_ML2_Subnet')
    @mock.patch('networking_fortinet.common.resources.DhcpServer')
    def test_delete_subnet_postcommit(self, Fortinet_Static_Router,
                                      RouterStatic, Fortinet_ML2_Subnet,
                                      DhcpServer):
        self.driver.initialize()
        mech_context = self._setup_subnet_context()
        router_record = mock.Mock()
        router_record.edit_id = 123
        with mock.patch('networking_fortinet.db.models.query_record',
                        return_value=router_record):
            self.driver.delete_subnet_postcommit(mech_context)

    @mock.patch('networking_fortinet.db.models.Fortinet_Firewall_Address')
    @mock.patch('networking_fortinet.common.resources.FirewallAddress')
    @mock.patch('networking_fortinet.common.resources.FirewallAddrgrp')
    @mock.patch('networking_fortinet.db.models.Fortinet_Firewall_Policy')
    @mock.patch('networking_fortinet.common.resources.FirewallPolicy')
    @mock.patch('networking_fortinet.db.models.Fortinet_Vlink_Vlan_Allocation')
    @mock.patch('networking_fortinet.db.models.Fortinet_Vlink_IP_Allocation')
    @mock.patch('networking_fortinet.db.models.Fortinet_Vdom_Vlink')
    @mock.patch('networking_fortinet.common.resources.VdomLink')
    @mock.patch('networking_fortinet.common.resources.VlanInterface')
    @mock.patch('networking_fortinet.db.models.Fortinet_Static_Router')
    @mock.patch('networking_fortinet.common.resources.RouterStatic')
    @mock.patch('networking_fortinet.db.models.Fortinet_Firewall_IPPool')
    @mock.patch('networking_fortinet.common.resources.FirewallIppool')
    @mock.patch('networking_fortinet.db.models.Fortinet_ML2_ReservedIP')
    @mock.patch('networking_fortinet.common.resources.DhcpServerRsvAddr')
    @mock.patch('networking_fortinet.db.models.Fortinet_Interface_subip')
    def test_create_port_precommit_and_del_port_postcommit(self,
                                   Fortinet_Firewall_Address,
                                   FirewallAddress, FirewallAddrgrp,
                                   Fortinet_Firewall_Policy, FirewallPolicy,
                                   Fortinet_Vlink_Vlan_Allocation,
                                   Fortinet_Vlink_IP_Allocation,
                                   Fortinet_Vdom_Vlink, VdomLink,
                                   VlanInterface,
                                   Fortinet_Static_Router, RouterStatic,
                                   Fortinet_Firewall_IPPool, FirewallIppool,
                                   Fortinet_ML2_ReservedIP,
                                   DhcpServerRsvAddr,
                                   Fortinet_Interface_subip):
        self.driver.initialize()
        mech_context = self._setup_port_context()
        namespace = mock.Mock()
        namespace.vdom = 'osvdm1234'
        subnet = mock.Mock()
        subnet.cidr = '172.20.21.0/24'
        subnet.edit_id = '123'
        subnet.vdom = 'osvdm123'
        fwaddr = mock.Mock()
        fwaddr.name = 'cool'
        fwaddr.group = 'addrgrp1'
        fwpolicy = mock.Mock()
        fwpolicy.edit_id = '123'
        fwpolicy.vdom = 'osvdm123'
        fwippool = mock.Mock()
        fwippool.edit_id = '123'
        fwippool.vdom = 'osvdmext'
        fwippool.name = '172.20.21.1'
        router = mock.Mock()
        router.tenant_id = 'test'
        router.edit_id = '123'
        router.vdom = 'osvdm123'
        router.gw_port_id = None
        vlink = mock.Mock()
        vlink.inf_name_ext_vdom = 'vlink_1'
        vlink.id = '1234'
        vlink.ip = '169.254.0.10'
        vlink.edit_id = '123'
        vlink.vdom = 'osvdm123'
        vlink.inf_name_int_vdom = 'vlink_0'
        fgt_intf = mock.Mock()
        fgt_intf.name = 'port32'
        fgt_intf.ip = '1.1.1.1'
        subip = mock.Mock()
        subip.ip = '172.20.21.1 255.255.255.0'
        reserveip = mock.Mock()
        reserveip.edit_id = '123'
        reserveip.ip = '172.20.21.123'
        reserveip.mac = 'aa:aa:aa:aa:aa:aa'
        with mock.patch('networking_fortinet.db.models.query_record',
                        side_effect=[namespace, subnet, fwaddr]):
            with mock.patch('networking_fortinet.db.models.query_records',
                        side_effect=[[fwaddr]]):
                self.driver.create_port_precommit(mech_context)
        with mock.patch('networking_fortinet.db.models.query_record',
                        side_effect=[subnet, subnet, fwpolicy, fwaddr]):
            with mock.patch('networking_fortinet.db.models.query_records',
                        side_effect=[[fwaddr]]):
                self.driver.delete_port_postcommit(mech_context)
        mech_context.current['device_owner'] = 'network:router_gateway'
        with mock.patch('networking_fortinet.db.models.query_record',
                        side_effect=[namespace, subnet, 'external_net',
                                     router, vlink, subnet, fgt_intf]):
            with mock.patch('networking_fortinet.common.utils.getip',
                            side_effect=['169.254.0.10', '160.254.0.11']):
                    with mock.patch(
                        'networking_fortinet.db.models.query_records',
                        side_effect=[[subip]]):
                        self.driver.create_port_precommit(mech_context)
        with mock.patch('networking_fortinet.db.models.query_record',
                        side_effect=[subnet, subnet, 'external', subnet,
                                     fwpolicy, fwippool, router, namespace,
                                     vlink, vlink.ip, router, vlink,
                                     namespace]):
            with mock.patch('networking_fortinet.db.models.query_records',
                            side_effect=[[subip], [router]]):
                with mock.patch('networking_fortinet.db.models.query_count',
                                return_value=0):
                    self.driver.delete_port_postcommit(mech_context)
        mech_context.current['device_owner'] = 'network:compute:None'
        with mock.patch('networking_fortinet.db.models.query_record',
                        side_effect=[namespace, subnet, [reserveip], subnet]):
            self.driver.create_port_precommit(mech_context)
        with mock.patch('networking_fortinet.db.models.query_records',
                        side_effect=[[reserveip]]):
            with mock.patch('networking_fortinet.db.models.query_record',
                            side_effect=[subnet] * 3):
                self.driver.delete_port_postcommit(mech_context)

    def test_create_port_postcommit(self):
        mech_context = self._setup_port_context()
        with mock.patch('networking_fortinet.tasks.tasks.TaskManager'):
            self.driver.create_port_postcommit(mech_context)


class Fake_context(object):
    def __init__(self):
        engine = session.EngineFacade.from_config(cfg.CONF)
        if not [driver for driver in cfg.CONF.ml2.type_drivers
                if driver in SUPPORTED_DR]:
            exit()
        self.session = engine.get_session(autocommit=True,
                                          expire_on_commit=False)
        self.request_id = 'fake_migration_context'


class Fake_mech_context(object):
    def __init__(self, **kwargs):
        for key, value in six.iteritems(kwargs):
            setattr(self, key, value)
