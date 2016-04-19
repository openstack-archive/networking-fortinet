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
from netaddr import IPAddress
from netaddr import IPNetwork
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.api import extensions as neutron_extensions
from neutron.api.v2 import attributes as attr
from neutron.common import constants as l3_consts
from neutron import context as neutron_context
from neutron.db import l3_db
from neutron import manager
from neutron.plugins.common import constants as const
from neutron_fwaas.db.firewall import firewall_db
from neutron_fwaas.db.firewall import firewall_router_insertion_db
import neutron_fwaas.extensions as extensions
from neutron_fwaas.extensions import firewall as fw_ext

from networking_fortinet._i18n import _LE
from networking_fortinet.common import config
from networking_fortinet.common import constants as constants
from networking_fortinet.common import utils as utils
from networking_fortinet.db import models as fortinet_db
from networking_fortinet.tasks import constants as t_consts
from networking_fortinet.tasks import tasks

LOG = logging.getLogger(__name__)
FORTINET_FW = "fortinet_fw"
FORTINET_FW_PLUGIN = "fortinet_fw_plugin"


class FortinetFirewallPlugin(
    firewall_db.Firewall_db_mixin,
    firewall_router_insertion_db.FirewallRouterInsertionDbMixin):
    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    neutron_extensions.append_api_extensions_path(extensions.__path__)
    supported_extension_aliases = ["fwaas", "fwaasrouterinsertion"]
    path_prefix = fw_ext.FIREWALL_PREFIX

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
        self._fortigate = config.fgt_info
        self._driver = config.get_apiclient()
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()
        firewall_db.subscribe()

    def _rpc_update_firewall(self, context, firewall_id):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        super(FortinetFirewallPlugin, self).update_firewall(
            context, firewall_id, status_update)
        fw_with_rules = self._make_firewall_dict_with_rules(context,
                                                            firewall_id)
        # this is triggered on an update to fw rule or policy, no
        # change in associated routers.
        fw_with_rules['add-router-ids'] = self.get_firewall_routers(
                context, firewall_id)
        fw_with_rules['del-router-ids'] = []
        self._apply_firewall(context, **fw_with_rules)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._rpc_update_firewall(context, firewall_id)

    def _ensure_update_firewall(self, context, firewall_id):
        fwall = self.get_firewall(context, firewall_id)
        if fwall['status'] in [const.PENDING_CREATE,
                               const.PENDING_UPDATE,
                               const.PENDING_DELETE]:
            raise fw_ext.FirewallInPendingState(firewall_id=firewall_id,
                                                pending_state=fwall['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy and 'firewall_list' in firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._ensure_update_firewall(context, firewall_id)

    def _ensure_update_firewall_rule(self, context, firewall_rule_id):
        fw_rule = self.get_firewall_rule(context, firewall_rule_id)
        if 'firewall_policy_id' in fw_rule and fw_rule['firewall_policy_id']:
            self._ensure_update_firewall_policy(context,
                                                fw_rule['firewall_policy_id'])

    def _get_routers_for_create_firewall(self, tenant_id, context, firewall):
        # pop router_id as this goes in the router association db
        # and not firewall db
        LOG.debug("# _get_routers_for_create_firewall called Fortinet_plugin")
        router_ids = firewall['firewall'].pop('router_ids', None)
        if router_ids == attr.ATTR_NOT_SPECIFIED:
            # old semantics router-ids keyword not specified pick up
            # all routers on tenant.
            l3_plugin = manager.NeutronManager.get_service_plugins().get(
                const.L3_ROUTER_NAT)
            ctx = neutron_context.get_admin_context()
            routers = l3_plugin.get_routers(ctx)
            router_ids = [
                router['id']
                for router in routers
                if router['tenant_id'] == tenant_id]
            # validation can still fail this if there is another fw
            # which is associated with one of these routers.
            self.validate_firewall_routers_not_in_use(context, router_ids)
            return router_ids
        else:
            if not router_ids:
                # This indicates that user specifies no routers.
                return []
            else:
                # some router(s) provided.
                self.validate_firewall_routers_not_in_use(context, router_ids)
                return router_ids

    def create_firewall(self, context, firewall):
        LOG.debug("create_firewall() called Fortinet_plugin")
        tenant_id = firewall['firewall']['tenant_id']
        fw_new_rtrs = self._get_routers_for_create_firewall(
            tenant_id, context, firewall)
        if not fw_new_rtrs:
            # no messaging to agent needed, and fw needs to go
            # to INACTIVE(no associated rtrs) state.
            status = const.INACTIVE
            fw = super(FortinetFirewallPlugin, self).create_firewall(
                context, firewall, status)
            fw['router_ids'] = []
            return fw
        else:
            fw = super(FortinetFirewallPlugin, self).create_firewall(
                context, firewall)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        fw_with_rtrs = {'fw_id': fw['id'], 'router_ids': fw_new_rtrs}
        self.set_routers_for_firewall(context, fw_with_rtrs)
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = []

        self._apply_firewall(context, **fw_with_rules)
        return fw

    def update_firewall(self, context, id, firewall):
        LOG.debug("Fortinet_plugin update_firewall() called, "
                  "id is %(id)s, firewall is %(fw)s",
                  {'id': id, 'fw': firewall})
        self._ensure_update_firewall(context, id)
        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        if router_ids is not None:
            if router_ids == []:
                # This indicates that user is indicating no routers.
                fw_new_rtrs = []
            else:
                self.validate_firewall_routers_not_in_use(
                    context, router_ids, id)
                fw_new_rtrs = router_ids
            self.update_firewall_routers(context, {'fw_id': id,
                'router_ids': fw_new_rtrs})
        else:
            # router-ids keyword not specified for update pick up
            # existing routers.
            fw_new_rtrs = self.get_firewall_routers(context, id)

        if not fw_new_rtrs and not fw_current_rtrs:
            # no messaging to agent needed, and we need to continue
            # in INACTIVE state
            firewall['firewall']['status'] = const.INACTIVE
            fw = super(FortinetFirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = []
            return fw
        else:
            firewall['firewall']['status'] = const.PENDING_UPDATE
            fw = super(FortinetFirewallPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        # determine rtrs to add fw to and del from
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = list(
            set(fw_current_rtrs).difference(set(fw_new_rtrs)))

        # last-router drives agent to ack with status to set state to INACTIVE
        fw_with_rules['last-router'] = not fw_new_rtrs

        LOG.debug("## update_firewall %s: Add Routers: %s, Del Routers: %s",
            fw['id'],
            fw_with_rules['add-router-ids'],
            fw_with_rules['del-router-ids'])
        self._apply_firewall(context, **fw_with_rules)
        #self.agent_rpc.update_firewall(context, fw_with_rules)
        return fw

    def update_firewall_for_delete_router(self, context, router_id):
        LOG.debug("fwaas delete_router() called, router_id: %(rtid)s",
                  {'rtid': router_id})
        cls = firewall_router_insertion_db.FirewallRouterAssociation
        db_fw_rt = fortinet_db.query_record(context, cls, router_id=router_id)
        if not db_fw_rt:
            return None
        firewall = {u'firewall': {'router_ids': []}}
        return self.update_firewall(context, db_fw_rt.fw_id, firewall)

    def delete_db_firewall_object(self, context, id):
        super(FortinetFirewallPlugin, self).delete_firewall(context, id)

    def delete_firewall(self, context, id):
        LOG.debug("Fortinet_plugin delete_firewall() called, fw_id %(id)s",
                  {'id': id})
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, id))

        status = {"firewall": {"status": const.PENDING_DELETE}}
        super(FortinetFirewallPlugin, self).update_firewall(
            context, id, status)
        # Reflect state change in fw_with_rules
        fw_with_rules['del-router-ids'] = self.get_firewall_routers(
            context, id)
        self._apply_firewall(context, **fw_with_rules)
        self.delete_db_firewall_object(context, id)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug("update_firewall_policy called, "
                  "id =%(id)s, firewall_policy=%(fp)s",
                  {'id': id, 'fp': firewall_policy})
        self._ensure_update_firewall_policy(context, id)
        firewall_policy_old = self.get_firewall_policy(context, id)
        firewall_rule_ids = firewall_policy_old.get('firewall_rules', [])
        tenant_id = firewall_policy_old.get('tenant_id', None)
        fwp = super(FortinetFirewallPlugin,
                    self).update_firewall_policy(context, id, firewall_policy)
        for fwr_id in firewall_rule_ids:
            fw_rule = self.get_firewall_rule(context, fwr_id)
            self._delete_firewall_rule(context, tenant_id, **fw_rule)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def create_firewall_rule(self, context, firewall_rule):
        """
        :param context:
        :param firewall_rule:
        firewall_rule={'firewall_rule': {... }}
        :return:
        """
        LOG.debug("create_firewall_rule() firewall_rule=%(fwr)s",
                  {'fwr': firewall_rule})
        return super(FortinetFirewallPlugin,
            self).create_firewall_rule(context, firewall_rule)

    def delete_firewall_rule(self, context, id):
        super(FortinetFirewallPlugin, self).delete_firewall_rule(context, id)

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug("update_firewall_rule() id: %(id)s, "
                  "firewall_rule: %(firewall_rule)s",
                  {'id': id, 'firewall_rule': firewall_rule})
        try:
            fwr = self._update_firewall_rule_dict(context, id, firewall_rule)
            self._update_firewall_rule(context, id, fwr)
            self._ensure_update_firewall_rule(context, id)
            fwr = super(FortinetFirewallPlugin,
                        self).update_firewall_rule(context, id, firewall_rule)
            utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)
            return fwr
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("update_firewall_rule %(fwr)s failed"),
                          {'fwr': firewall_rule})
                utils._rollback_on_err(self, context, e)

    def insert_rule(self, context, id, rule_info):
        self._ensure_update_firewall_policy(context, id)
        try:
            fwp = super(FortinetFirewallPlugin,
                    self).insert_rule(context, id, rule_info)
            self._rpc_update_firewall_policy(context, id)
            utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)
            return fwp
        except Exception as e:
            with excutils.save_and_reraise_exception():
                self.remove_rule(context, id, rule_info)
                utils._rollback_on_err(self, context, e)

    def remove_rule(self, context, id, rule_info):
        LOG.debug("Fortinet_plugin remove_rule() called")
        self._ensure_update_firewall_policy(context, id)
        if rule_info.get('firewall_rule_id', None):
            firewall_rule = self._get_firewall_rule(
                context, rule_info['firewall_rule_id'])
            fwr = self._make_firewall_rule_dict(firewall_rule)
            self._delete_firewall_rule(context, fwr['tenant_id'], **fwr)
        fwp = super(FortinetFirewallPlugin, self).remove_rule(
            context, id, rule_info)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def get_firewalls(self, context, filters=None, fields=None):
        LOG.debug("fwaas get_firewalls() called, filters=%(filters)s, "
                  "fields=%(fields)s",
                  {'filters': filters, 'fields': fields})
        fw_list = super(FortinetFirewallPlugin, self).get_firewalls(
                        context, filters, fields)
        for fw in fw_list:
            fw_current_rtrs = self.get_firewall_routers(context, fw['id'])
            fw['router_ids'] = fw_current_rtrs
        return fw_list

    def get_firewall(self, context, id, fields=None):
        LOG.debug("fwaas get_firewall() called")
        res = super(FortinetFirewallPlugin, self).get_firewall(
                        context, id, fields)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        res['router_ids'] = fw_current_rtrs
        return res

    def _apply_firewall(self, context, **fw_with_rules):
        tenant_id = fw_with_rules['tenant_id']
        default_fwr = self._make_default_firewall_rule_dict(tenant_id)
        try:
            if fw_with_rules.get('del-router-ids', None):
                for fwr in list(fw_with_rules.get('firewall_rule_list', None)):
                    self._delete_firewall_rule(context, tenant_id, **fwr)
                if default_fwr:
                    self._delete_firewall_rule(
                        context, tenant_id, **default_fwr)
                self.update_firewall_status(
                    context, fw_with_rules['id'], const.INACTIVE)

            if fw_with_rules.get('add-router-ids', None):
                vdom = getattr(
                    fortinet_db.Fortinet_ML2_Namespace.query_one(
                        context, tenant_id=tenant_id), 'vdom', None)
                if not vdom:
                    raise fw_ext.FirewallInternalDriverError(
                        driver='Fortinet_fwaas_plugin')
                if default_fwr:
                    self._add_firewall_rule(context, tenant_id, **default_fwr)
                for fwr in reversed(
                        list(fw_with_rules.get('firewall_rule_list', None))):
                    self._add_firewall_rule(context, tenant_id, **fwr)
                self.update_firewall_status(
                    context, fw_with_rules['id'], const.ACTIVE)
            else:
                self.update_firewall_status(
                    context, fw_with_rules['id'], const.INACTIVE)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("apply_firewall %(fws)s failed"),
                          {'fws': fw_with_rules})
                utils._rollback_on_err(self, context, e)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)

    def _add_firewall_rule(self, context, fwp_tenant_id, **fwr):
        """
        :param obj:
        :param context:
        :param kwargs: dictionary, firewall rule
        firewall_rule: {'source_ip_address': u'192.176.10.0/24',... }
        :return:
        """
        LOG.debug("# _add_firewall_rule() called")
        namespace = fortinet_db.Fortinet_ML2_Namespace.query_one(
            context, tenant_id=fwp_tenant_id)
        vdom = getattr(namespace, 'vdom', None)
        if not vdom or not fwr:
            return None
        inf_int, inf_ext = utils.get_vlink_intf(
            self, context, vdom=namespace.vdom)
        srcaddr = self._add_fwr_ip_address(
            context, vdom, place='source_ip_address', **fwr)
        dstaddr = self._add_fwr_ip_address(
            context, vdom, place='destination_ip_address', **fwr)
        service = self._add_fwr_service(context, vdom, **fwr)
        action = self._get_fwr_action(**fwr)
        profiles = self._get_fwp_profiles(action)
        match_vip = 'enable'
        name = fwr.get('name', '')
        # add a basic firewall rule('accept': incoming, 'deny': bidirectional)
        fortinet_fwp = utils.add_fwpolicy_to_head(self, context,
                                                  vdom=vdom,
                                                  srcaddr=srcaddr['name'],
                                                  srcintf='any',
                                                  dstaddr=dstaddr['name'],
                                                  dstintf='any',
                                                  service=service['name'],
                                                  match_vip=match_vip,
                                                  action=action,
                                                  comments=name,
                                                  **profiles)
        utils.add_record(self, context,
                         fortinet_db.Fortinet_FW_Rule_Association,
                         fwr_id=fwr['id'],
                         fortinet_pid=fortinet_fwp.id,
                         type=constants.TYPE_INT)

        if action in ['accept']:
            # if allow, for the outgoing traffic it need to enable nat
            fortinet_fwp = utils.add_fwpolicy_to_head(self, context,
                                                      vdom=vdom,
                                                      srcaddr=srcaddr['name'],
                                                      srcintf='any',
                                                      dstaddr=dstaddr['name'],
                                                      dstintf=inf_int,
                                                      nat='enable',
                                                      service=service['name'],
                                                      action=action,
                                                      comments=name,
                                                      **profiles)
            utils.add_record(self, context,
                             fortinet_db.Fortinet_FW_Rule_Association,
                             fwr_id=fwr['id'],
                             fortinet_pid=fortinet_fwp.id,
                             type=constants.TYPE_EXT)

    def _update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug("# _add_firewall_rule() called")
        fwps_int = fortinet_db.Fortinet_FW_Rule_Association.query_all(
            context, fwr_id=id, type=constants.TYPE_INT)
        fwps_ext = fortinet_db.Fortinet_FW_Rule_Association.query_all(
            context, fwr_id=id, type=constants.TYPE_EXT)
        if fwps_ext and fwps_int:
            fwps = fwps_int + fwps_ext
        else:
            fwps = fwps_int or fwps_ext
        if not fwps:
            return
        firewall_rule.setdefault('id', id)
        srcaddr = self._make_fortinet_fwaddress_dict(
            place='source_ip_address', **firewall_rule)
        dstaddr = self._make_fortinet_fwaddress_dict(
            place='destination_ip_address', **firewall_rule)
        service = self._make_fortinet_fwservice_dict(**firewall_rule)
        action = self._get_fwr_action(**firewall_rule)
        profiles = self._get_fwp_profiles(action)
        for fwp in fwps_int:
            vdom = fwp.fortinet_policy.vdom
            if service['name'] != 'ALL':
                utils.set_fwservice(self, context, vdom=vdom, **service)
            if srcaddr['name'] != 'all':
                utils.set_fwaddress(self, context, vdom=vdom, **srcaddr)
            if dstaddr['name'] != 'all':
                utils.set_fwaddress(self, context, vdom=vdom, **dstaddr)
        # check whether related firewall policies need to update
        fwp = fwps_int[0].fortinet_policy
        name = firewall_rule.setdefault('name', fwp.comments)
        if fwp.srcaddr == srcaddr['name'] and fwp.action == action and \
            fwp.dstaddr == dstaddr['name'] and fwp.service == service['name']:
            return
        if action in ['accept']:
            for fwp in fwps:
                fortinet_fwp = utils.set_fwpolicy(self, context,
                                                  id=fwp.fortinet_pid,
                                                  srcaddr=srcaddr['name'],
                                                  dstaddr=dstaddr['name'],
                                                  service=service['name'],
                                                  action=action,
                                                  comments=name,
                                                  **profiles)
                if not fwps_ext:
                    inf_int, inf_ext = utils.get_vlink_intf(
                        self, context, vdom=fortinet_fwp.vdom)
                    utils.add_fwaas_subpolicy(self, context,
                                              before=fortinet_fwp.edit_id,
                                              vdom=fortinet_fwp.vdom,
                                              srcaddr=srcaddr['name'],
                                              dstaddr=dstaddr['name'],
                                              dstintf=inf_int,
                                              nat='enable',
                                              service=service['name'],
                                              action=action,
                                              comments=name,
                                              fwr_id=id,
                                              type=constants.TYPE_EXT,
                                              **profiles)
        elif action in ['deny']:
            for fwp_ext in fwps_ext:
                utils.delete_fwaas_subpolicy(self, context,
                                             fwr_id=fwp_ext.fwr_id,
                                             fortinet_pid=fwp_ext.fortinet_pid)
            for fwp in fwps_int:
                utils.set_fwpolicy(self, context,
                                   id=fwp.fortinet_pid,
                                   srcaddr=srcaddr['name'],
                                   dstaddr=dstaddr['name'],
                                   service=service['name'],
                                   action=action,
                                   comments=name,
                                   **profiles)
        for fwp in fwps_int:
            vdom = fwp.fortinet_policy.vdom
            if service['name'] == 'ALL':
                #delete all old services if exist
                utils.delete_fwservice(self, context, vdom=vdom, name=id)
            if srcaddr['name'] == 'all':
                name = constants.PREFIX['source_ip_address'] + id
                utils.delete_fwaddress(self, context, vdom=vdom, name=name)
            if dstaddr['name'] == 'all':
                name = constants.PREFIX['destination_ip_address'] + id
                utils.delete_fwaddress(self, context, vdom=vdom, name=name)

    def _delete_firewall_rule(self, context, fwp_tenant_id, **fwr):
        """
        :param obj:
        :param context:
        :param kwargs: dictionary, firewall rule
        firewall_rule: {'source_ip_address': u'192.176.10.0/24',... }
        :return:
        """
        # need to consider shared firewall rules
        LOG.debug("# _delete_firewall_rule() called")
        namespace = fortinet_db.Fortinet_ML2_Namespace.query_one(
            context, tenant_id=fwp_tenant_id)
        if not namespace:
            return None
        fwp_assed = fortinet_db.Fortinet_FW_Rule_Association.query_all(
            context, fwr_id=fwr['id'])
        for fwp in fwp_assed:
            fortinet_db.delete_record(
                context, fortinet_db.Fortinet_FW_Rule_Association,
                fwr_id=fwp.fwr_id, fortinet_pid=fwp.fortinet_pid)
            utils.delete_fwpolicy(
                self, context, id=fwp.fortinet_pid, vdom=namespace.vdom)

        if fwr.get('source_ip_address', None):
            srcaddr = constants.PREFIX['source_ip_address'] + fwr['id']
            utils.delete_fwaddress(
                self, context, vdom=namespace.vdom, name=srcaddr)
        if fwr.get('destination_ip_address', None):
            dstaddr = constants.PREFIX['destination_ip_address'] + fwr['id']
            utils.delete_fwaddress(
                self, context, vdom=namespace.vdom, name=dstaddr)
        self._delete_fwr_service(context, namespace.vdom, **fwr)

    def _update_firewall_rule_dict(self, context, id, firewall_rule):
        fwr = firewall_rule.get('firewall_rule', firewall_rule)
        fwr_db = self._get_firewall_rule(context, id)
        if fwr_db.firewall_policy_id:
            fwp_db = self._get_firewall_policy(context,
                                               fwr_db.firewall_policy_id)
            if 'shared' in fwr and not fwr['shared']:
                if fwr_db['tenant_id'] != fwp_db['tenant_id']:
                    raise fw_ext.FirewallRuleInUse(firewall_rule_id=id)
        fwr.setdefault('source_port',
                       self._get_port_range_from_min_max_ports(
                           fwr_db['source_port_range_min'],
                           fwr_db['source_port_range_max']))
        fwr.setdefault('destination_port',
                       self._get_port_range_from_min_max_ports(
                           fwr_db['destination_port_range_min'],
                           fwr_db['destination_port_range_max']))
        keys = ['name', 'protocol', 'action', 'shared', 'ip_version',
                'source_ip_address', 'destination_ip_address', 'enabled']
        for key in keys:
            fwr.setdefault(key, fwr_db[key])
        return fwr

    def _make_default_firewall_rule_dict(self, tenant_id):
        if tenant_id and self._fortigate["enable_default_fwrule"]:
            return {'id': tenant_id,
                    'tenant_id': tenant_id,
                    'name': '_default_rule_deny_all',
                    'description': '_default_rule_deny_all',
                    'protocol': None,
                    'source_ip_address': None,
                    'source_port': None,
                    'destination_ip_address': None,
                    'destination_port': None,
                    'action': 'deny'}
        else:
            return {}

    def _add_fwr_ip_address(self, context, vdom,
                            place='source_ip_address', **fwr):
        fwaddress = self._make_fortinet_fwaddress_dict(
            place=place, vdom=vdom, **fwr)
        utils.add_fwaddress(self, context, **fwaddress)
        return fwaddress

    def _make_fortinet_fwaddress_dict(self, place='source_ip_address',
                                      vdom=None, **fwr):
        fwaddress = {}
        if place not in ['source_ip_address', 'destination_ip_address']:
            raise ValueError("_add_fwr_ip_address() value error of where")
        if vdom:
            fwaddress.setdefault('vdom', vdom)
        if fwr.get(place, None):
            fwaddress.setdefault('name', constants.PREFIX[place] + fwr['id'])
            fwaddress.setdefault('subnet', utils.get_subnet(fwr[place]))
        else:
            fwaddress.setdefault('name', 'all')
        return fwaddress

    def _add_fwr_service(self, context, vdom, **fwr):
        kw_service = self._make_fortinet_fwservice_dict(vdom=vdom, **fwr)
        utils.add_fwservice(self, context, **kw_service)
        return kw_service

    def _make_fortinet_fwservice_dict(self, vdom=None, **fwr):
        LOG.debug("_make_fortinet_fwservice_dict() fwr=%(fwr)s", {'fwr': fwr})
        kw_service = {}
        if vdom:
            kw_service.setdefault('vdom', vdom)
        if fwr['protocol'] in ['any', None] and \
            not fwr['destination_port'] and not fwr['source_port']:
            # SamSu: The firewall service 'all' was already added by default
            kw_service.setdefault('name', 'ALL')
        else:
            portrange = ':'.join([
                utils.port_range(fwr['destination_port']),
                utils.port_range(fwr['source_port'])])
            if fwr['protocol'] in ['tcp']:
                kw_service.setdefault('tcp_portrange', portrange)
            elif fwr['protocol'] in ['udp']:
                kw_service.setdefault('udp_portrange', portrange)
            elif fwr['protocol'] in ['icmp']:
                kw_service.setdefault('protocol', 'ICMP')
            kw_service.setdefault('name', fwr['id'])
            kw_service.setdefault('comment', fwr.get('name', ''))
        return kw_service

    def _delete_fwr_service(self, context, vdom, **fwr):
        LOG.debug("# _delete_fwr_service() fwr=%(fwr)s", {'fwr': fwr})
        if fwr['protocol'] in ['any', None] and \
            not fwr['destination_port'] and not fwr['source_port']:
            return None
        else:
            return utils.delete_fwservice(
                self, context, vdom=vdom, name=fwr['id'])

    def _get_fwr_action(self, **fwr):
        if fwr.get('action', None) in ['allow']:
            action = 'accept'
        else:
            action = 'deny'
        return action

    def _get_fwp_profiles(self, action):
        profiles = {
            'av_profile': None,
            'webfilter_profile': None,
            'ips_sensor': None,
            'application_list': None,
            'ssl_ssh_profile': None
        }
        if action in ['allow', 'accept']:
            for key in profiles:
                profiles[key] = self._fortigate[key]
        return profiles

    def _get_fip_before_id(self, context, fwr_id):
        fwp_assed = fortinet_db.Fortinet_FW_Rule_Association.query_one(
                context, type=constants.TYPE_EXT, fwr_id=fwr_id)
        if not fwp_assed:
            fwp_assed = fortinet_db.Fortinet_FW_Rule_Association.query_one(
                context, type=constants.TYPE_INT, fwr_id=fwr_id)
        fwp = fortinet_db.query_record(context,
                                       fortinet_db.Fortinet_Firewall_Policy,
                                       id=fwp_assed.fortinet_pid)
        return getattr(fwp, 'edit_id', None)

    def _get_fips_in_fw(self, context, tenant_id, fw_net):
        fw_fips = []
        if not fw_net:
            return fw_fips
        namespace = fortinet_db.Fortinet_ML2_Namespace.query_one(
            context, tenant_id=tenant_id)
        if not namespace:
            return fw_fips
        db_fips = fortinet_db.query_records(
            context, l3_db.FloatingIP, tenant_id=tenant_id,
            status=l3_consts.FLOATINGIP_STATUS_ACTIVE)
        for fip in db_fips:
            if getattr(fip, 'fixed_ip_address', None) and \
                    IPAddress(fip.fixed_ip_address) in IPNetwork(fw_net):
                fw_fips.append((fip.id, fip.floating_ip_address))
        return fw_fips
