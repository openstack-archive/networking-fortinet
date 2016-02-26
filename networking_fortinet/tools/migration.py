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

import time
import sys

from oslo_config import cfg
from oslo_log import log as logging
from neutron import version

from neutron.common import constants as l3_constants

from neutron.db import models_v2, l3_db

from neutron.db.external_net_db import ExternalNetwork

from oslo_db.sqlalchemy import session
import neutron.plugins.ml2.models as ml2_db

from networking_fortinet.common import resources
from networking_fortinet.common import utils
from networking_fortinet.ml2 import mech_fortinet
from networking_fortinet.services.l3_router import l3_fortinet
from networking_fortinet.tasks import tasks
from networking_fortinet.tasks import constants as t_consts
from networking_fortinet.db import models as fortinet_db

ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW

#streamlog = handlers.ColorHandler()
LOG = logging.getLogger(None).logger
#LOG.addHandler(streamlog)

CFG_ARGS = [
             '--config-file',
             '/etc/neutron/neutron.conf',
             '--config-file',
             '/etc/neutron/plugin.ini'
           ]

CFG_KWARGS = {}
SUPPORTED_DR = ['vlan']

cfg.CONF(args=CFG_ARGS, project='neutron',
         version='%%prog %s' % version.version_info.release_string(),
         **CFG_KWARGS)
cfg.CONF.import_group('ml2_fortinet',
                'networking_fortinet.common.config')

class Progress(object):
    def __init__(self, total, name=''):
       self.i = 0
       self.total = total if total else 1
       print "Starting %s:" % name

    def __enter__(self):
        return self

    def update(self):
        self.i += 1
        self.percent = float(self.i)/self.total
        sys.stdout.write('\r[{0:<30}] {1:.0%}'.format(
                '=' * int(round(self.percent * 29)) + '>', self.percent
            ))
        sys.stdout.flush()
        time.sleep(0.2)

    def __exit__(self, type, value, traceback):
        print ""


class Fake_context(object):
    def __init__(self, args=CFG_ARGS, kwargs=CFG_KWARGS):
        engine = session.EngineFacade.from_config(cfg.CONF)
        if not [driver for driver in cfg.CONF.ml2.type_drivers
                       if driver in SUPPORTED_DR]:
            LOG.error(_("The supported type driver %(sdr)s are not in the "
                          "ml2 type drivers %(td)s in the plugin config file.")
                        % {'sdr': SUPPORTED_DR,
                           'td': cfg.CONF.ml2.type_drivers})
            exit()
        self.session = engine.get_session(autocommit=True,
                                          expire_on_commit=False)
        self.request_id = 'migration_context'

class Fake_mech_context(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.iteritems():
            setattr(self, key, value)

class Fake_FortinetL3ServicePlugin(l3_fortinet.FortinetL3ServicePlugin):
    def __init__(self):
        self._fortigate = None
        self._driver = None
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()
        self.Fortinet_init()

    def create_router(self, context, router):
        LOG.debug("create_router: router=%s" % (router))
        # Limit one router per tenant
        if not router.get('router', None):
            return
        tenant_id = router['router']['tenant_id']
        with context.session.begin(subtransactions=True):
            try:
                namespace = utils.add_vdom(self, context, tenant_id=tenant_id)
                utils.add_vlink(self, context, namespace.vdom)
            except Exception as e:
                LOG.error("Failed to create_router router=%(router)s",
                          {"router": router})
                resources.Exinfo(e)
                utils._rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)


    def add_router_interface(self, context, port):
        """creates vlnk on the fortinet device."""
        db_namespace = fortinet_db.query_record(context,
                                fortinet_db.Fortinet_ML2_Namespace,
                                tenant_id=port['tenant_id'])
        vlan_inf = utils.get_intf(context, port['network_id'])
        int_intf, ext_intf = utils.get_vlink_intf(self, context,
                                       vdom=db_namespace.vdom)
        utils.add_fwpolicy(self, context,
                           vdom=db_namespace.vdom,
                           srcintf=vlan_inf,
                           dstintf=int_intf,
                           nat='enable')

    def _get_floatingip(self, context, id):
        return fortinet_db.query_record(context, l3_db.FloatingIP, id=id)


    def create_floatingip(self, context, floatingip, returned_obj):
        """Create floating IP.
        """
        LOG.debug(_("create_floatingip: floatingip=%s" % floatingip))
        self._allocate_floatingip(context, returned_obj)
        if returned_obj.get('port_id', None):
            if not floatingip['floatingip'].get('fixed_ip_address', None):
                floatingip['floatingip']['fixed_ip_address'] = \
                    returned_obj.get('fixed_ip_address')
            self._associate_floatingip(context, returned_obj['id'],
                                       floatingip)
            self.update_floatingip_status(context, returned_obj,
                                l3_constants.FLOATINGIP_STATUS_ACTIVE,
                                id=returned_obj['id'])
        return returned_obj

def init_mech_driver():
    mech_driver = mech_fortinet.FortinetMechanismDriver()
    mech_driver.initialize()
    return mech_driver

def reset(dictionary):
    for key, value in dictionary.iteritems():
        if isinstance(value, list):
            dictionary[key] = []
        elif isinstance(value, dict):
            dictionary[key] = {}
        elif isinstance(value, (int, long)):
            dictionary[key] = 0
        elif isinstance(value, (str, unicode, type(None))):
            dictionary[key] = None
        elif isinstance(value, bool):
            dictionary[key] = False
        else:
            raise TypeError
    return dictionary

def cls2dict(record, dictionary, **kwargs):
    for key, value in record.__dict__.iteritems():
        if key in dictionary:
            dictionary[key] = value
        elif key in kwargs:
            dictionary[kwargs[key]] = value
    return dictionary

def network_migration(context, mech_driver):
    """
    # networks, ml2_network_segments
    network =  {
        #'status': 'ACTIVE',
        #'subnets': [],
        'name': u'test-net',
        #'provider: physical_network': u'physnet1',
        #'admin_state_up': True,
        'tenant_id': u'11513667f4ee4a14acb0985659459988',
        'provider: network_type': u'vlan',
        'router:external': False,
        #'shared': False,
        'id': 'ff0a1d64-ce30-4ed0-ba37-597eaf8976f0',
        #'provider: segmentation_id': 1200L
    }
    # ml2_network_segments
    segments = [{
        'segmentation_id': 1200L,
        'physical_network': u'physnet1',
        'id': u'e7dfa4fb-038a-4aad-b6fa-73afba788888',
        'network_type': u'vlan'
    }]
    """
    net =  {
        'name': '',
        'tenant_id': '',
        'provider: network_type': '',
        'router:external': False,
        'id': '',
    }

    segment = {
        'segmentation_id': 0,
        'physical_network': '',
        'id': '',
        'network_type': ''
    }
    records = fortinet_db.query_records(context, models_v2.Network)
    with Progress(len(records), 'network_migration') as p:
        for record in records:
            reset(net)
            reset(segment)
            db_seg = fortinet_db.query_record(context, ml2_db.NetworkSegment,
                                              network_id=record.id)
            cls2dict(record, net)
            db_extnet = fortinet_db.query_record(context, ExternalNetwork,
                                              network_id=record.id)
            if db_extnet:
                net['router:external'] = True

            cls2dict(db_seg, segment)
            net['provider: network_type'] = db_seg.network_type
            mech_context = Fake_mech_context(_plugin_context=context,
                                             current=net,
                                             network_segments=[segment])
            mech_driver.create_network_postcommit(mech_context)
            p.update()


def subnet_migration(context, mech_driver):
    # table subnets
    subnet =  {
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
    ipallocation_pool = {
        'start': '172.20.21.2',
        'end': '172.20.21.254'
    }
    records = fortinet_db.query_records(context, models_v2.Subnet)
    with Progress(len(records), 'subnet_migration') as p:
        for record in records:
            dns_nameservers = []
            reset(subnet)
            reset(ipallocation_pool)
            db_ipallocation = fortinet_db.query_record(context,
                                                models_v2.IPAllocationPool,
                                                subnet_id=record.id)
            cls2dict(db_ipallocation, ipallocation_pool,
                     first_ip='start', last_ip='end')
            db_dnssrvs = fortinet_db.query_records(context,
                                                   models_v2.DNSNameServer,
                                                   subnet_id=record.id)

            for dns in db_dnssrvs:
                dns_nameservers.append(dns.address)
            cls2dict(record, subnet)
            subnet['dns_nameservers'] = dns_nameservers
            subnet['allocation_pools'] = [ipallocation_pool]
            mech_context = Fake_mech_context(_plugin_context=context,
                                             current=subnet)
            mech_driver.create_subnet_postcommit(mech_context)
            p.update()

def port_migration(context, mech_driver, l3_driver):
    """
    :param mech_driver:
    :param context:
    :return:
    # table ports
    port
    {
        'status': 'DOWN',
        'binding: host_id': '',
        'allowed_address_pairs': [],
        'device_owner': 'network: router_interface',
        'binding: profile': {

        },
        # table ipallocations
        'fixed_ips': [{
            'subnet_id': u'f645b09c-a34a-42fb-9c14-b999e43a54c7',
            'ip_address': u'172.20.21.1'
        }],
        'id': 'fb66def6-bd5e-44a0-a3f7-7c0e8e08d9ff',
        'security_groups': [],
        'device_id': u'e4020c65-7003-468b-a34d-31af297397a0',
        'name': '',
        'admin_state_up': True,
        'network_id': u'f8e34426-ccf7-429c-b726-3809d54cabdc',
        'tenant_id': u'11513667f4ee4a14acb0985659456f24',
        'binding: vif_details': {
        },
        'binding: vnic_type': 'normal',
        'binding: vif_type': 'unbound',
        'mac_address': u'00: 0c: 29: d9: 18: 3f'
    }
    """
    port = {
        'device_owner': 'network: router_interface',
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
    ipallocation = {
        'subnet_id': u'f645b09c-a34a-42fb-9c14-b999e43a54c7',
        'ip_address': u'172.20.21.1'
    }
    MAC = utils.get_mac(mech_driver, context)
    records = fortinet_db.query_records(context, models_v2.Port)
    with Progress(len(records), 'port_migration') as p:
         for record in records:
            reset(port)
            cls2dict(record, port)
            if port['fixed_ips']:
                fixed_ips = []
                for fixed_ip in port['fixed_ips']:
                    cls2dict(fixed_ip, ipallocation)
                    fixed_ips.append(ipallocation)
                port['fixed_ips'] = fixed_ips
            if port['device_owner'] in [ROUTER_INTF, ROUTER_GW] and \
               MAC not in port['mac_address']:
                port['mac_address'] = MAC
                if not fortinet_db.query_count(context, models_v2.Port,
                    mac_address=MAC, network_id=record.network_id):
                    fortinet_db.update_record(context, record,
                                              mac_address=MAC)
            mech_context = Fake_mech_context(_plugin_context=context,
                                             current=port)
            mech_driver.create_port_precommit(mech_context)
            mech_driver.create_port_postcommit(mech_context)
            db_routerport = fortinet_db.query_record(context,
                                                     l3_db.RouterPort,
                                                     port_id=record.id)
            if getattr(db_routerport, 'port_type', None) in [ROUTER_INTF]:
                l3_driver.add_router_interface(context, port)
            p.update()


def router_migration(context, l3_driver):
    """
    # table routers, router_extra_attributes
    router={
        u'router': {
            'external_gateway_info': None,
            u'name': u'adm_router',
            u'admin_state_up': True,
            u'tenant_id': u'01c2468ab38b4d4490a39765bb87cb00',
            'distributed': 'fakedistributed',
            'ha': 'fakeha'
        }
    }
    """
    router_obj = {
        'name': 'adm_router',
        'admin_state_up': True,
        'tenant_id': u'01c2468ab38b4d4490a39765bb87cb00'
    }
    router = {'router': router_obj}

    records = fortinet_db.query_records(context, l3_db.Router)
    with Progress(len(records), 'router_migration') as p:
        for record in records:
            reset(router_obj)
            cls2dict(record, router_obj)
            l3_driver.create_router(context, router)
            p.update()


def floatingip_migration(context, l3_driver):
    """
    # table floatingips, ipallocations
    floatingip = {
        u'floatingip': {
            u'floating_network_id': u'2bdcaa63-22c5-4e58-8e2e-8f35bef7f513',
            'tenant_id': u'11513667f4ee4a14acb0985659456f24',
            'fixed_ip_address': None,
            'port_id': None
        }
    }
    returned_obj
    {
        'floating_network_id': u'2bdcaa63-22c5-4e58-8e2e-8f35bef7f513',
        'router_id': None,
        'fixed_ip_address': None,
        'floating_ip_address': u'10.160.37.139',
        'tenant_id': u'11513667f4ee4a14acb0985659456f24',
        'status': 'DOWN',
        'port_id': None,
        'id': '78764016-da62-42fd-96a4-f2bd0510b5bc'
    }
    """

    returned_obj = {
        'fixed_ip_address': None,
        'floating_ip_address': u'10.160.37.139',
        'tenant_id': u'11513667f4ee4a14acb0985659456f24',
        'status': 'DOWN',
        'port_id': None,
        'id': '78764016-da62-42fd-96a4-f2bd0510b5bc'
        }
    floatingip = {'floatingip': returned_obj}
    records = fortinet_db.query_records(context, l3_db.FloatingIP)
    with Progress(len(records), 'floatingip_migration') as p:
        for record in records:
            reset(returned_obj)
            cls2dict(record, returned_obj, fixed_port_id='port_id')
            l3_driver.create_floatingip(context, floatingip, returned_obj)
            p.update()


def main():
    try:
        context = Fake_context()
        mech_driver = init_mech_driver()
        l3_driver = Fake_FortinetL3ServicePlugin()
        router_migration(context, l3_driver)
        network_migration(context, mech_driver)
        subnet_migration(context, mech_driver)
        port_migration(context, mech_driver, l3_driver)
        floatingip_migration(context, l3_driver)
    except Exception as e:
        raise(e)
    print "\nmigration completed.\n"


if __name__ == "__main__":
    main()

