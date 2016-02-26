# Copyright 2015 Fortinet Inc.
# All rights reserved.
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
#


"""Implentation of FortiOS service Plugin."""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.db import l3_db
from neutron import manager
from neutron.plugins.common import constants as service_consts
from neutron.plugins.ml2 import db
from neutron.services.l3_router import l3_router_plugin as router

from networking_fortinet._i18n import _LE
from networking_fortinet.common import config
from networking_fortinet.common import constants as const
from networking_fortinet.common import resources
from networking_fortinet.common import utils
from networking_fortinet.db import models as fortinet_db
from networking_fortinet.tasks import constants as t_consts
from networking_fortinet.tasks import tasks

# TODO(samsu): the folowing two imports just for testing purpose
# TODO(samsu): need to be deleted later
from neutron.db import models_v2

DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP


LOG = logging.getLogger(__name__)


class FortinetL3ServicePlugin(router.L3RouterPlugin):
    """Fortinet L3 service Plugin."""

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        """Initialize Fortinet L3 service Plugin."""
        super(FortinetL3ServicePlugin, self).__init__()
        self._fortigate = None
        self._driver = None
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()
        self.Fortinet_init()

    def Fortinet_init(self):
        """Fortinet specific initialization for this class."""
        LOG.debug("FortinetL3ServicePlugin_init")
        self._fortigate = config.fgt_info
        self._driver = config.get_apiclient()
        self.enable_fwaas = 'fwaas_fortinet' in cfg.CONF.service_plugins

    def create_router(self, context, router):
        LOG.debug("create_router: router=%s" % (router))
        # Limit one router per tenant
        if not router.get('router', None):
            return
        tenant_id = router['router']['tenant_id']
        if fortinet_db.query_count(context, l3_db.Router,
                                   tenant_id=tenant_id):
            raise Exception(_("FortinetL3ServicePlugin:create_router "
                              "Only support one router per tenant"))
        with context.session.begin(subtransactions=True):
            try:
                namespace = utils.add_vdom(self, context, tenant_id=tenant_id)
                utils.add_vlink(self, context, namespace.vdom)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Failed to create_router router=%(router)s"),
                              {"router": router})
                    utils._rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)
        return super(FortinetL3ServicePlugin, self).\
            create_router(context, router)

    def update_router(self, context, id, router):
        LOG.debug("update_router: id=%(id)s, router=%(router)s",
                  {'id': id, 'router': router})
        return (super(FortinetL3ServicePlugin, self).
                update_router(context, id, router))

    def delete_router(self, context, id):
        LOG.debug("delete_router: router id=%s" % (id))
        try:
            if self.enable_fwaas:
                fw_plugin = manager.NeutronManager.get_service_plugins().get(
                    service_consts.FIREWALL)
                fw_plugin.update_firewall_for_delete_router(context, id)
            with context.session.begin(subtransactions=True):
                router = fortinet_db.query_record(context, l3_db.Router, id=id)
                super(FortinetL3ServicePlugin, self).delete_router(context, id)
                if getattr(router, 'tenant_id', None):
                    utils.delete_vlink(self, context, router.tenant_id)
                    utils.delete_vdom(self, context,
                                      tenant_id=router.tenant_id)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Failed to delete_router routerid=%(id)s"),
                          {"id": id})
                resources.Exinfo(e)

    def add_router_interface(self, context, router_id, interface_info):
        """creates vlnk on the fortinet device."""
        LOG.debug("FortinetL3ServicePlugin.add_router_interface: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})
        with context.session.begin(subtransactions=True):
            info = super(FortinetL3ServicePlugin, self).add_router_interface(
                context, router_id, interface_info)
            port = db.get_port(context.session, info['port_id'])
            port['admin_state_up'] = True
            port['port'] = port
            LOG.debug("FortinetL3ServicePlugin: "
                      "context=%(context)s"
                      "port=%(port)s "
                      "info=%(info)r",
                      {'context': context, 'port': port, 'info': info})
            interface_info = info
            subnet = self._core_plugin._get_subnet(context,
                                                   interface_info['subnet_id'])
            network_id = subnet['network_id']
            tenant_id = port['tenant_id']
            port_filters = {'network_id': [network_id],
                            'device_owner': [DEVICE_OWNER_ROUTER_INTF]}
            port_count = self._core_plugin.get_ports_count(context,
                                                           port_filters)
            # port count is checked against 2 since the current port is already
            # added to db
            if port_count == 2:
                # This subnet is already part of some router
                LOG.error(_LE("FortinetL3ServicePlugin: adding redundant "
                              "router interface is not supported"))
                raise Exception(_("FortinetL3ServicePlugin:adding redundant "
                                  "router interface is not supported"))
            try:
                db_namespace = fortinet_db.query_record(context,
                                        fortinet_db.Fortinet_ML2_Namespace,
                                        tenant_id=tenant_id)
                vlan_inf = utils.get_intf(context, network_id)
                int_intf, ext_intf = utils.get_vlink_intf(self, context,
                                               vdom=db_namespace.vdom)
                utils.add_fwpolicy(self, context,
                                   vdom=db_namespace.vdom,
                                   srcintf=vlan_inf,
                                   dstintf=int_intf,
                                   nat='enable')

            except Exception as e:
                LOG.error(_LE("Failed to create Fortinet resources to add "
                            "router interface. info=%(info)s, "
                            "router_id=%(router_id)s"),
                          {"info": info, "router_id": router_id})
                utils._rollback_on_err(self, context, e)
                with excutils.save_and_reraise_exception():
                    self.remove_router_interface(context, router_id,
                                                 interface_info)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        """Deletes vlink, default router from Fortinet device."""
        LOG.debug("FortinetL3ServicePlugin.remove_router_interface called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        with context.session.begin(subtransactions=True):
            info = (super(FortinetL3ServicePlugin, self).
                    remove_router_interface(context, router_id,
                                            interface_info))
            try:
                subnet = self._core_plugin._get_subnet(context,
                                                       info['subnet_id'])
                tenant_id = subnet['tenant_id']
                network_id = subnet['network_id']
                vlan_inf = utils.get_intf(context, network_id)
                db_namespace = fortinet_db.query_record(context,
                                        fortinet_db.Fortinet_ML2_Namespace,
                                        tenant_id=tenant_id)
                utils.delete_fwpolicy(self, context,
                                      vdom=db_namespace.vdom,
                                      srcintf=vlan_inf)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Fail remove of interface from Fortigate "
                                  "router interface. info=%(info)s, "
                                  "router_id=%(router_id)s"),
                             {"info": info, "router_id": router_id})
        return info

    def create_floatingip(self, context, floatingip):
        """Create floating IP.

        :param context: Neutron request context
        :param floatingip: data for the floating IP being created
        :returns: A floating IP object on success

        As the l3 router plugin asynchronously creates floating IPs
        leveraging the l3 agent, the initial status for the floating
        IP object will be DOWN.
        """
        LOG.debug("create_floatingip: floatingip=%s", floatingip)
        returned_obj = (super(FortinetL3ServicePlugin, self).
                        create_floatingip(context, floatingip))
        try:
            self._allocate_floatingip(context, returned_obj)
            if returned_obj.get('port_id', None):
                if not floatingip['floatingip'].get('fixed_ip_address', None):
                    floatingip['floatingip']['fixed_ip_address'] = (
                        returned_obj.get('fixed_ip_address'))
                self._associate_floatingip(context, returned_obj['id'],
                                           floatingip)
                self.update_floatingip_status(context, returned_obj,
                                    l3_constants.FLOATINGIP_STATUS_ACTIVE,
                                    id=returned_obj['id'])
            return returned_obj
        except Exception as e:
            with excutils.save_and_reraise_exception():
                resources.Exinfo(e)
                super(FortinetL3ServicePlugin, self).delete_floatingip(
                    context, returned_obj['id'])

    def delete_floatingip(self, context, id):
        LOG.debug("delete_floatingip called() id=%s", id)
        fip = fortinet_db.query_record(context, l3_db.FloatingIP, id=id)
        if fip and getattr(fip, 'fixed_port_id', None):
            self._disassociate_floatingip(context, id)
            super(FortinetL3ServicePlugin, self).disassociate_floatingips(
                context, fip['fixed_port_id'])
        self._release_floatingip(context, id)

    def update_floatingip_status(self, context, res, status, **kwargs):
        if res.get('status', None):
            res['status'] = status
        record = fortinet_db.query_record(context, l3_db.FloatingIP, **kwargs)
        fortinet_db.update_record(context, record, status=status)

    def update_floatingip(self, context, id, floatingip):
        if floatingip['floatingip']['port_id']:
            # floating ip associate with VM port.
            try:
                res = (super(FortinetL3ServicePlugin, self).
                       update_floatingip(context, id, floatingip))
                if not floatingip['floatingip'].get('fixed_ip_address', None):
                    floatingip['floatingip']['fixed_ip_address'] = (res.
                        get('fixed_ip_address'))
                self._associate_floatingip(context, id, floatingip)
                self.update_floatingip_status(context, res,
                                l3_constants.FLOATINGIP_STATUS_ACTIVE, id=id)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    resources.Exinfo(e)
                    super(FortinetL3ServicePlugin,
                          self).disassociate_floatingips(
                        context, floatingip['floatingip']['port_id'])
        else:
            # disassociate floating ip.
            self._disassociate_floatingip(context, id)
            res = (super(FortinetL3ServicePlugin, self).
                   update_floatingip(context, id, floatingip))
            self.update_floatingip_status(context, res,
                            l3_constants.FLOATINGIP_STATUS_DOWN, id=id)
        return res if res else None

    def _associate_floatingip(self, context, id, floatingip):
        try:
            l3db_fip = self._get_floatingip(context, id)
            db_namespace = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                    tenant_id=l3db_fip.tenant_id)

            db_fip = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_FloatingIP_Allocation,
                            floating_ip_address=l3db_fip.floating_ip_address,
                            allocated=True)
            int_intf, ext_intf = utils.get_vlink_intf(self, context,
                                                      vdom=db_namespace.vdom)
            mappedip = utils.get_ipaddr(db_fip.ip_subnet, 0)
            fixed_ip_address = floatingip['floatingip']['fixed_ip_address']
            utils.add_vip(self, context,
                          vdom=db_namespace.vdom,
                          name=db_fip.floating_ip_address,
                          extip=mappedip,
                          extintf=int_intf,
                          mappedip=fixed_ip_address)

            db_ip = fortinet_db.query_record(context, models_v2.IPAllocation,
                                port_id=floatingip['floatingip']['port_id'])
            vlan_inf = utils.get_intf(context, db_ip.network_id)
            utils.add_fwpolicy(self, context,
                               vdom=db_namespace.vdom,
                               srcintf=int_intf,
                               dstintf=vlan_inf,
                               dstaddr=db_fip.floating_ip_address,
                               nat='enable')

            utils.add_fwaddress(self, context,
                                name=fixed_ip_address,
                                vdom=db_namespace.vdom,
                                subnet="%s 255.255.255.255" % fixed_ip_address,
                                associated_interface=vlan_inf)

            db_fwpolicy = utils.add_fwpolicy(self, context,
                               vdom=db_namespace.vdom,
                               srcintf=vlan_inf,
                               srcaddr=fixed_ip_address,
                               dstintf=int_intf,
                               poolname=mappedip)

            if self.enable_fwaas:
                fwrass = fortinet_db.Fortinet_FW_Rule_Association.query_one(
                    context, fwr_id=db_namespace.tenant_id)
                default_fwp = getattr(fwrass, 'fortinet_policy', None)
                if getattr(default_fwp, 'edit_id', None):
                    utils.head_firewall_policy(self, context,
                                               vdom=db_namespace.vdom,
                                               id=db_fwpolicy.edit_id,
                                               after=default_fwp.edit_id)
                    _headed = True
            if '_headed' not in locals():
                utils.head_firewall_policy(self, context,
                                           vdom=db_namespace.vdom,
                                           id=db_fwpolicy.edit_id)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                utils._rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)

    def _disassociate_floatingip(self, context, id):
        l3db_fip = self._get_floatingip(context, id)
        db_namespace = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                    tenant_id=l3db_fip.tenant_id)
        db_fip = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_FloatingIP_Allocation,
                            floating_ip_address=l3db_fip.floating_ip_address,
                            allocated=True)
        int_intf, ext_intf = utils.get_vlink_intf(self, context,
                                               vdom=db_namespace.vdom)
        db_ip = fortinet_db.query_record(context, models_v2.IPAllocation,
                                         port_id=l3db_fip.fixed_port_id)
        vlan_inf = utils.get_intf(context, db_ip.network_id)
        mappedip = utils.get_ipaddr(db_fip.ip_subnet, 0)
        utils.delete_fwpolicy(self, context,
                              vdom=db_namespace.vdom,
                              srcintf=vlan_inf,
                              srcaddr=l3db_fip.fixed_ip_address,
                              dstintf=int_intf,
                              poolname=mappedip)

        utils.delete_fwaddress(self, context,
                               name=l3db_fip.fixed_ip_address,
                               vdom=db_namespace.vdom)

        utils.delete_fwpolicy(self, context,
                              vdom=db_namespace.vdom,
                              dstaddr=db_fip.floating_ip_address)

        utils.delete_vip(self, context,
                         vdom=db_namespace.vdom,
                         name=db_fip.floating_ip_address)

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        fip = fortinet_db.query_record(context, l3_db.FloatingIP,
                                       fixed_port_id=port_id)
        if fip and getattr(fip, 'id', None):
            self._disassociate_floatingip(context, fip.id)
        return super(FortinetL3ServicePlugin,
                     self).disassociate_floatingips(context,
                                                    port_id,
                                                    do_notify=do_notify)

    def _add_interface_by_subnet(self, context, router, subnet_id, owner):
        LOG.debug("_add_interface_by_subnet(): router=%(router)s, "
                  "subnet_id=%(subnet_id)s, owner=%(owner)s",
                  {'router': router, 'subnet_id': subnet_id, 'owner': owner})
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        if not subnet['gateway_ip']:
            msg = _('Subnet for router interface must have a gateway IP')
            raise n_exc.BadRequest(resource='router', msg=msg)
        self._check_for_dup_router_subnet(context, router,
                                          subnet['network_id'],
                                          subnet_id,
                                          subnet['cidr'])
        fixed_ip = {'ip_address': subnet['gateway_ip'],
                    'subnet_id': subnet['id']}
        return (self._core_plugin.create_port(context, {
            'port':
            {'tenant_id': subnet['tenant_id'],
             'network_id': subnet['network_id'],
             'fixed_ips': [fixed_ip],
             'mac_address': utils.get_mac(self, context),
             'admin_state_up': True,
             'device_id': router.id,
             'device_owner': owner,
             'name': ''}}), [subnet], True)

    def _allocate_floatingip(self, context, obj):
        """
        1. mapping floatingip to the one of a pair of internal ips based on
           the vip function.
        2. add another ip of the ip pair to the secondaryip list of
           the external interface.

        obj example:
        {
            'floating_network_id': u'1c1dbecc-9dac-4311-a346-f147a04c8dc8',
            'router_id': None,
            'fixed_ip_address': None,
            'floating_ip_address': u'10.160.37.113',
            'tenant_id': u'3998b33381fb48f694369689065a3760',
            'status': 'DOWN',
            'port_id': None,
            'id': '5ec1b08b-77c1-4e39-80ac-224ee937ee9f'
        }

        The floatingip is a instance of neutron.db.l3_db.FloatingIP, example:
        {
            tenant_id=u'3998b33381fb48f694369689065a3760',
            id=u'25e1588a-5ec5-4fbc-bdef-eff8713da8f8',
            floating_ip_address=u'10.160.37.111',
            floating_network_id=u'1c1dbecc-9dac-4311-a346-f147a04c8dc8',
            floating_port_id=u'4b4120d4-77f9-4f82-b823-05876929a1c4',
            fixed_port_id=None,
            fixed_ip_address=None,
            router_id=None,
            last_known_router_id=None,
            status=u'DOWN'
        }
        """
        with context.session.begin(subtransactions=True):
            try:
                db_namespace = utils.add_vdom(self, context,
                                              tenant_id=obj['tenant_id'])

                db_fip = utils.add_record(self, context,
                                fortinet_db.Fortinet_FloatingIP_Allocation,
                                vdom=db_namespace.vdom,
                                floating_ip_address=obj['floating_ip_address'],
                                vip_name=obj['floating_ip_address'])
                mappedip = utils.get_ipaddr(db_fip.ip_subnet, 0)
                utils.add_vip(self, context,
                              vdom=const.EXT_VDOM,
                              name=db_fip.vip_name,
                              extip=db_fip.floating_ip_address,
                              extintf='any',
                              mappedip=mappedip)

                int_intf, ext_intf = utils.get_vlink_intf(self, context,
                                                       vdom=db_namespace.vdom)

                utils.add_fwpolicy(self, context,
                                   vdom=const.EXT_VDOM,
                                   dstintf=ext_intf,
                                   dstaddr=db_fip.vip_name,
                                   nat='enable')

                utils.add_routerstatic(self, context,
                                       vdom=const.EXT_VDOM,
                                       dst="%s 255.255.255.255" % mappedip,
                                       device=ext_intf,
                                       gateway=const.DEF_GW)

                utils.add_fwippool(self, context,
                                   name=db_fip.floating_ip_address,
                                   vdom=const.EXT_VDOM,
                                   startip=db_fip.floating_ip_address)

                utils.add_fwaddress(self, context,
                                    name=mappedip,
                                    vdom=const.EXT_VDOM,
                                    subnet="%s 255.255.255.255" % mappedip)

                db_fwpolicy = utils.add_fwpolicy(self, context,
                                   vdom=const.EXT_VDOM,
                                   srcintf=ext_intf,
                                   srcaddr=mappedip,
                                   dstintf=self._fortigate['ext_interface'],
                                   poolname=db_fip.floating_ip_address)
                utils.head_firewall_policy(self, context,
                                           vdom=const.EXT_VDOM,
                                           id=db_fwpolicy.edit_id)

                utils.add_fwippool(self, context,
                                   name=mappedip,
                                   vdom=db_namespace.vdom,
                                   startip=mappedip)
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    utils._rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)

    def _release_floatingip(self, context, id):
        """
        :param context:
        :param id: the floatingip id in neutron.db.l3_db.FloatingIP.
        {
                tenant_id=u'3998b33381fb48f694369689065a3760',
                id=u'25e1588a-5ec5-4fbc-bdef-eff8713da8f8',
                floating_ip_address=u'10.160.37.111',
                floating_network_id=u'1c1dbecc-9dac-4311-a346-f147a04c8dc8',
                floating_port_id=u'4b4120d4-77f9-4f82-b823-05876929a1c4',
                fixed_port_id=None,
                fixed_ip_address=None,
                router_id=None,
                last_known_router_id=None,
                status=u'DOWN'
        }
        :return:
        """
        with context.session.begin(subtransactions=True):
            l3db_fip = self._get_floatingip(context, id)
            tenant_id = l3db_fip.tenant_id
            db_namespace = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                    tenant_id=tenant_id)

            db_fip = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_FloatingIP_Allocation,
                            floating_ip_address=l3db_fip.floating_ip_address,
                            allocated=True)
            if not db_fip or not db_namespace:
                return

            int_intf, ext_intf = utils.get_vlink_intf(self, context,
                                                     vdom=db_namespace.vdom)
            mappedip = utils.get_ipaddr(db_fip.ip_subnet, 0)

            utils.delete_fwippool(self, context,
                                  name=mappedip,
                                  vdom=db_namespace.vdom,
                                  startip=mappedip)

            utils.delete_fwpolicy(self, context,
                                  vdom=const.EXT_VDOM,
                                  srcintf=ext_intf,
                                  srcaddr=mappedip,
                                  dstintf=self._fortigate['ext_interface'],
                                  poolname=db_fip.floating_ip_address)

            utils.delete_fwaddress(self, context,
                                   name=mappedip,
                                   vdom=const.EXT_VDOM,
                                   subnet="%s 255.255.255.255" % mappedip)

            utils.delete_fwippool(self, context,
                                  name=db_fip.floating_ip_address,
                                  vdom=const.EXT_VDOM,
                                  startip=db_fip.floating_ip_address)

            utils.delete_routerstatic(self, context,
                                      vdom=const.EXT_VDOM,
                                      dst="%s 255.255.255.255" % mappedip,
                                      device=ext_intf,
                                      gateway=const.DEF_GW)

            utils.delete_fwpolicy(self, context,
                                  vdom=const.EXT_VDOM,
                                  dstintf=ext_intf,
                                  dstaddr=l3db_fip.floating_ip_address)

            utils.delete_vip(self, context,
                             vdom=const.EXT_VDOM,
                             name=db_fip.vip_name,
                             extip=db_fip.floating_ip_address,
                             extintf='any',
                             mappedip=mappedip)

            fortinet_db.delete_record(context,
                            fortinet_db.Fortinet_FloatingIP_Allocation,
                            vdom=db_namespace.vdom,
                            floating_ip_address=db_fip.floating_ip_address,
                            vip_name=db_fip.floating_ip_address)
            super(FortinetL3ServicePlugin, self).delete_floatingip(context, id)
            utils.delete_vlink(self, context, tenant_id)
            utils.delete_vdom(self, context, tenant_id=tenant_id)
