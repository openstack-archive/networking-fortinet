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

from fortiosclient import exception
import netaddr
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.db.models import l3 as l3_db
from neutron.db.models import segment as segments_db
from neutron.db import models_v2

from networking_fortinet.common import constants as const
from networking_fortinet.common import resources as resources
from networking_fortinet.db import models as fortinet_db
from networking_fortinet.tasks import constants as t_consts

LOG = logging.getLogger(__name__)


def add_record(obj, context, cls, **kwargs):
    res = cls.add_record(context, **kwargs)
    if not res:
        return res
    if res.get('rollback', {}):
        obj.task_manager.add(getid(context), **res['rollback'])
    return res.get('result', None)


def op(obj, context, func, **data):
    res = func(obj._driver, data)
    if res.get('rollback', {}):
        obj.task_manager.add(getid(context), **res['rollback'])
    return res.get('result', res)


def check(obj, context, vdom, resource=resources.VlanInterface):
    vlink_vlan = fortinet_db.query_record(context,
                     fortinet_db.Fortinet_Vlink_Vlan_Allocation, vdom=vdom)
    if vlink_vlan:
        try:
            op(obj, context, resource.get,
               vdom=vdom, name=vlink_vlan.inf_name_int_vdom)
            op(obj, context, resource.get,
               vdom=const.EXT_VDOM, name=vlink_vlan.inf_name_ext_vdom)
        except exception.ResourceNotFound as e:
            import inspect
            caller = inspect.stack()[1][3]
            LOG.debug("## Check vlink interface failed on the %(func)s.",
                      {'func': caller})
            resources.Exinfo(e)


def getid(context):
    id = getattr(context, 'request_id', None)
    if not id:
        if not getattr(context, 'session', None):
            return const.INIT_TASK_ID
        else:
            raise ValueError("not get request_id")
    return id


def port_range(range):
    """
    :param range:  openstack port range format '200: 300'
    :return: fortigate port range format: '100-200'
    e.g. tcp-portrange 100-200:300-400
    """
    if range:
        return '-'.join([p.strip() for p in range.split(':')])
    else:
        return '1-65535'


def get_mac(obj, context, interface=None):
    if not interface:
        interface = obj._fortigate['int_interface']
    res = op(obj, context, resources.VlanInterface.get, name=interface)
    if 200 == res['http_status']:
        return res['results'][0]['macaddr']
    return None


def getip(ipsubnet, place):
    return "%s %s" % (get_ipaddr(ipsubnet, place), get_netmask(ipsubnet))


def get_ipaddr(ip_subnet, place=1):
    return str(netaddr.IPNetwork(ip_subnet)[place])


def get_netmask(ip_subnet):
    return str(netaddr.IPNetwork(ip_subnet).netmask)


def get_subnet(ip_subnet):
    """
    :param ip_subnet:  input '192.168.138.0/24'
    :return: '192.168.138.0 255.255.255.0'
    """
    cidr = netaddr.IPNetwork(ip_subnet)
    return ' '.join([str(cidr.network), str(cidr.netmask)])


def get_segmentation_id(context, network_id):
    ml2_net_seg = fortinet_db.query_record(context,
                                           segments_db.NetworkSegment,
                                           network_id=network_id)
    return getattr(ml2_net_seg, 'segmentation_id', None)


def get_intf(context, network_id):
    vlanid = get_segmentation_id(context, network_id=network_id)
    return const.PREFIX['inf'] + str(vlanid) if vlanid else None


def backup_fields(record, **kwargs):
    rbkwargs = {}
    for key in kwargs:
        if hasattr(record, key):
            rbkwargs.setdefault(key, record.key)
    return rbkwargs


def update_status(obj, context, status):
    obj.task_manager.update_status(getid(context), status)


def _rollback_on_err(obj, context, err):
    update_status(obj, context, t_consts.TaskStatus.ROLLBACK)
    resources.Exinfo(err)


def _prepare_params(record, resource, *keys, **kwargs):
    if record:
        params = {key: getattr(record, key, None) for key in keys
                  if getattr(record, key, None)}
        #if 'id' in keys:
        #    params.setdefault('id', getattr(record, 'edit_id', None))
    else:
        LOG.debug("_prepare_params() called, record is None, "
                  "resource=%(res)s, kwargs=%(kwargs)s",
                  {'res': resource, 'kwargs': kwargs})
        params = {key: kwargs.get(key, None) for key in keys if key in kwargs}
    return params


def add_by_keys(obj, context, cls, resource, *keys, **kwargs):
    record = add_record(obj, context, cls, **kwargs)
    add_resource_with_keys(obj, context, record, resource, *keys, **kwargs)
    return record


def set_by_keys(obj, context, cls, resource, *keys, **kwargs):
    params = _prepare_params(None, resource, *keys, **kwargs)
    record = fortinet_db.query_record(context, cls, **params)
    if record:
        record = cls.update_record(context, record, **kwargs)
        set_resource_with_keys(obj, context, record, resource, *keys, **kwargs)
    else:
        record = add_by_keys(obj, context, cls, resource, *keys, **kwargs)
    return record


def delete_by_keys(obj, context, cls, resource, *keys, **kwargs):
    record = fortinet_db.query_record(context, cls, **kwargs)
    delete_resource_with_keys(obj, context, record, resource, *keys, **kwargs)
    return fortinet_db.delete_record(context, cls, **kwargs)


def add_resource_with_keys(obj, context, record, resource, *keys, **kwargs):
    params = _prepare_params(record, resource, *keys, **kwargs)
    try:
        op(obj, context, resource.get, **params)
    except exception.ResourceNotFound:
        return op(obj, context, resource.add, **kwargs)
    return None


def set_resource_with_keys(obj, context, record, resource, *keys, **kwargs):
    params = _prepare_params(record, resource, *keys, **kwargs)
    try:
        op(obj, context, resource.get, **params)
        for key in keys:
            kwargs.setdefault(key, params[key])
        return op(obj, context, resource.set, **kwargs)
    except exception.ResourceNotFound:
        LOG.debug("The resource %(rs)s with fields %(kws)s "
                  "is not exist, create a new one instead",
                  {"rs": resource, 'kws': kwargs})
        return op(obj, context, resource.add, **kwargs)


def delete_resource_with_keys(obj, context, record, resource, *keys, **kwargs):
    params = _prepare_params(record, resource, *keys, **kwargs)
    try:
        op(obj, context, resource.get, **params)
        return op(obj, context, resource.delete, **params)
    except exception.ResourceNotFound as e:
        resources.Exinfo(e)
    return None


def add_resource_with_name(obj, context, record, resource, **kwargs):
    return add_resource_with_keys(obj, context, record, resource,
                                  'vdom', 'name', **kwargs)


def set_resource_with_name(obj, context, record, resource, **kwargs):
    return set_resource_with_keys(obj, context, record, resource,
                                  'vdom', 'name', **kwargs)


def delete_resource_with_name(obj, context, record, resource, **kwargs):
    return delete_resource_with_keys(obj, context, record, resource,
                                     'vdom', 'name', **kwargs)


def add_resource_with_id(obj, context, record, resource, **kwargs):
    if getattr(record, 'edit_id', None):
        try:
            res = op(obj, context, resource.get,
                     vdom=record.vdom, id=record.edit_id)
            return res
        except exception.ResourceNotFound:
            pass
    else:
        # TODO(samsu): may add search existing data in devices later
        pass
    return op(obj, context, resource.add, **kwargs)


def set_resource_with_id(obj, context, record, resource, **kwargs):
    # because the name 'edit_id' in record is different with id in
    # the api templates, the id related function can not reuse the
    # related xx_keys function
    if getattr(record, 'edit_id', None):
        try:
            op(obj, context, resource.get, vdom=record.vdom, id=record.edit_id)
            if kwargs.get('id', None):
                del kwargs['id']
            kwargs.setdefault('id', str(record.edit_id))
            kwargs.setdefault('vdom', record.vdom)
            return op(obj, context, resource.set, **kwargs)
        except Exception as e:
            resources.Exinfo(e)
            raise e


def delete_resource_with_id(obj, context, record, resource):
    if getattr(record, 'edit_id', None):
        try:
            op(obj, context, resource.get, vdom=record.vdom, id=record.edit_id)
            return op(obj, context, resource.delete,
               vdom=record.vdom, id=record.edit_id)
        except Exception as e:
            resources.Exinfo(e)
    return None


def add_by_name(obj, context, cls, resource, **kwargs):
    return add_by_keys(obj, context, cls, resource, 'vdom', 'name', **kwargs)


def set_by_name(obj, context, cls, resource, **kwargs):
    return set_by_keys(obj, context, cls, resource, 'vdom', 'name', **kwargs)


def delete_by_name(obj, context, cls, resource, **kwargs):
    return delete_by_keys(obj, context, cls, resource,
                          'vdom', 'name', **kwargs)


def add_by_id(obj, context, cls, resource, **kwargs):
    record = add_record(obj, context, cls, **kwargs)
    res = add_resource_with_id(obj, context, record, resource, **kwargs)
    if not getattr(record, 'edit_id'):
        if res.get('results'):
            edit_id = res['results']['mkey']
        else:
            edit_id = res['mkey']
        cls.update_record(context, record, edit_id=edit_id)
    return record


def set_by_id(obj, context, cls, resource, **kwargs):
    params = _prepare_params(None, resource, 'vdom', 'id', **kwargs)
    record = fortinet_db.query_record(context, cls, **params)
    if record:
        cls.update_record(context, record, **kwargs)
        set_resource_with_id(obj, context, record, resource, **kwargs)
        return record
    else:
        return None


def delete_by_id(obj, context, cls, resource, **kwargs):
    record = fortinet_db.query_record(context, cls, **kwargs)
    delete_resource_with_id(obj, context, record, resource)
    return fortinet_db.delete_record(context, cls, **kwargs)


def add_vdom(obj, context, **kwargs):
    namespace = add_record(obj, context, fortinet_db.Fortinet_ML2_Namespace,
                           **kwargs)
    try:
        op(obj, context, resources.Vdom.get, name=namespace.vdom)
    except exception.ResourceNotFound:
        op(obj, context, resources.Vdom.add, name=namespace.vdom)
    return namespace


def delete_vdom(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_Namespace
    namespace = fortinet_db.query_record(context, cls, **kwargs)
    if namespace:
        tenant_id = namespace.tenant_id
        if not fortinet_db.query_count(context, l3_db.Router,
                                       tenant_id=tenant_id) and \
            not fortinet_db.query_count(context, models_v2.Network,
                                       tenant_id=tenant_id) and \
            not fortinet_db.query_count(context, l3_db.FloatingIP,
                                        tenant_id=tenant_id):
            try:
                op(obj, context, resources.Vdom.get, name=namespace.vdom)
                op(obj, context, resources.Vdom.delete, name=namespace.vdom)
            except Exception as e:
                resources.Exinfo(e)
            fortinet_db.delete_record(context, cls, **kwargs)
        else:
            db_routers = fortinet_db.query_records(context, l3_db.Router,
                                                   tenant_id=tenant_id)
            db_networks = fortinet_db.query_records(context, models_v2.Network,
                                                    tenant_id=tenant_id)
            db_fips = fortinet_db.query_records(context, l3_db.FloatingIP,
                                                tenant_id=tenant_id)
            LOG.debug("Keeping vdom, because existing db_routers: %(routers)s,"
                      "db_networks: %(networks)s, db_fips: %(fips)s",
                      {'routers': db_routers, 'networks': db_networks,
                       'fips': db_fips})
    return namespace


def add_vdomlink(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_Vdom_Vlink
    record = add_record(obj, context, cls, **kwargs)
    add_resource_with_keys(obj, context, record, resources.VdomLink,
                           'name', name=getattr(record, 'name', None))
    return record


def delete_vdomlink(obj, context, **kwargs):
    return delete_by_keys(obj, context, fortinet_db.Fortinet_Vdom_Vlink,
                          resources.VdomLink, 'name', **kwargs)


def add_vlanintf(obj, context, **kwargs):
    if 'alias' in kwargs and kwargs.get('alias', None):
        kwargs['alias'] = kwargs['alias'][:32]
    return add_by_name(obj, context,
                       fortinet_db.Fortinet_Interface,
                       resources.VlanInterface,
                       **kwargs)


def set_vlanintf(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_Interface
    record = cls.query_one(context, **kwargs)
    #backup_fields(record, **kwargs)
    if not record:
        cls.add_record(context, **kwargs)
        op(obj, context, resources.VlanInterface.set, **kwargs)


def delete_vlanintf(obj, context, **kwargs):
    return delete_by_name(obj, context,
                          fortinet_db.Fortinet_Interface,
                          resources.VlanInterface,
                          **kwargs)


def add_dhcpserver(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_Subnet
    record = add_record(obj, context, cls, **kwargs)
    kwargs.pop('subnet_id', None)
    res = add_resource_with_id(obj, context, record,
                               resources.DhcpServer, **kwargs)
    if not record.edit_id:
        if res.get('results'):
            edit_id = res['results']['mkey']
        else:
            edit_id = res['mkey']
        cls.update_record(context, record, edit_id=edit_id)


def set_dhcpserver(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_Subnet
    if 'subnet_id' in kwargs:
        record = cls.query_one(context, subnet_id=kwargs['subnet_id'])
        if record.edit_id:
            cls.update_record(context, record, **kwargs)
            kwargs.pop('subnet_id', None)
            kwargs.setdefault('id', record.edit_id)
            op(obj, context, resources.DhcpServer.set, **kwargs)


def delete_dhcpserver(obj, context, **kwargs):
    return delete_by_id(obj, context, fortinet_db.Fortinet_ML2_Subnet,
                        resources.DhcpServer, **kwargs)


def add_reservedip(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_ReservedIP
    add_record(obj, context, cls, **kwargs)
    db_reservedips = fortinet_db.query_records(context, cls,
                                        subnet_id=kwargs.get('subnet_id'))
    db_subnet = fortinet_db.query_record(context,
                                         fortinet_db.Fortinet_ML2_Subnet,
                                         subnet_id=kwargs.get('subnet_id'))
    if db_subnet:
        reserved_addresses = []
        for rsrvdip in db_reservedips:
            reserved_addresses.append({'id': rsrvdip.edit_id,
                                       'ip': rsrvdip.ip,
                                       'mac': rsrvdip.mac})

        op(obj, context, resources.DhcpServerRsvAddr.set,
           id=db_subnet.edit_id,
           vdom=kwargs.get('vdom'),
           reserved_address=jsonutils.dumps(reserved_addresses))
        # TODO(samsu): add rollback of dhcpserver set


def delete_reservedip(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_ReservedIP
    reserved_ip = fortinet_db.query_record(context, cls, **kwargs)

    if reserved_ip:
        db_reservedips = fortinet_db.query_records(context, cls,
                                        subnet_id=reserved_ip.subnet_id)
        db_reservedips.remove(reserved_ip)
        reserved_addresses = []
        for rsrvdip in db_reservedips:
            reserved_addresses.append({'id': rsrvdip.edit_id,
                                       'ip': rsrvdip.ip,
                                       'mac': rsrvdip.mac})
        db_subnet = fortinet_db.query_record(context,
                                             fortinet_db.Fortinet_ML2_Subnet,
                                             subnet_id=reserved_ip.subnet_id)
        if db_subnet:
            op(obj, context, resources.DhcpServerRsvAddr.set,
               id=db_subnet.edit_id,
               vdom=reserved_ip.vdom,
               reserved_address=jsonutils.dumps(reserved_addresses))
        fortinet_db.delete_record(context, cls, **kwargs)


def add_fwaddress(obj, context, **kwargs):
    return add_by_name(obj, context,
                       fortinet_db.Fortinet_Firewall_Address,
                       resources.FirewallAddress,
                       **kwargs)


def set_fwaddress(obj, context, **kwargs):
    return set_by_name(obj, context, fortinet_db.Fortinet_Firewall_Address,
                       resources.FirewallAddress, **kwargs)


def delete_fwaddress(obj, context, **kwargs):
    return delete_by_name(obj, context,
                          fortinet_db.Fortinet_Firewall_Address,
                          resources.FirewallAddress,
                          **kwargs)


def add_fwippool(obj, context, **kwargs):
    return add_by_name(obj, context,
                       fortinet_db.Fortinet_Firewall_IPPool,
                       resources.FirewallIppool,
                       **kwargs)


def delete_fwippool(obj, context, **kwargs):
    return delete_by_name(obj, context,
                          fortinet_db.Fortinet_Firewall_IPPool,
                          resources.FirewallIppool,
                          **kwargs)


def add_fwservice(obj, context, **kwargs):
    return add_resource_with_name(
        obj, context, None, resources.FirewallService, **kwargs)


def set_fwservice(obj, context, **kwargs):
    return set_resource_with_name(
        obj, context, None, resources.FirewallService, **kwargs)


def delete_fwservice(obj, context, **kwargs):
    return delete_resource_with_name(
        obj, context, None, resources.FirewallService, **kwargs)


def add_fwpolicy(obj, context, **kwargs):
    return add_by_id(obj, context,
                     fortinet_db.Fortinet_Firewall_Policy,
                     resources.FirewallPolicy,
                     **kwargs)


def add_fwpolicy_to_head(obj, context, **kwargs):
    sequence = {key: kwargs.pop(key, None) for key in ['before', 'after'] if
                key in kwargs}
    fwpolicy = add_fwpolicy(obj, context, **kwargs)
    sequence.setdefault('id', fwpolicy.edit_id)
    sequence.setdefault('vdom', fwpolicy.vdom)
    head_firewall_policy(obj, context, **sequence)
    return fwpolicy


def set_fwpolicy(obj, context, **kwargs):
    return set_by_id(obj, context,
                     fortinet_db.Fortinet_Firewall_Policy,
                     resources.FirewallPolicy,
                     **kwargs)


def delete_fwpolicy(obj, context, **kwargs):
    return delete_by_id(obj, context,
                        fortinet_db.Fortinet_Firewall_Policy,
                        resources.FirewallPolicy,
                        **kwargs)


def delete_fwpolicies(obj, context, like=False, **kwargs):
    if like:
        query_func = fortinet_db.Fortinet_Firewall_Policy.query_like
    else:
        query_func = fortinet_db.Fortinet_Firewall_Policy.query_all
    records = query_func(context, **kwargs)
    for record in records:
        delete_by_id(
            obj, context, fortinet_db.Fortinet_Firewall_Policy,
            resources.FirewallPolicy, vdom=record.vdom, edit_id=record.edit_id)


def head_firewall_policy(obj, context, **kwargs):
    """
    :param obj:
    :param context:
    :param kwargs: {
        'vdom': osvdmxx,
        'id': 5
    }
    :return:
    """
    if 'before' not in kwargs and 'after' not in kwargs and 'vdom' in kwargs:
        res = op(
            obj, context, resources.FirewallPolicy.get, vdom=kwargs['vdom'])
        if res.get('results'):
            head = res['results'][0]['policyid']
            kwargs.setdefault('before', head)
    if 'before' in kwargs and 'vdom' in kwargs:
        op(obj, context, resources.FirewallPolicy.move,
           vdom=kwargs['vdom'],
           id=kwargs['id'],
           before=kwargs['before'])
    elif 'after' in kwargs and 'vdom' in kwargs:
        op(obj, context, resources.FirewallPolicy.move,
           vdom=kwargs['vdom'],
           id=kwargs['id'],
           after=kwargs['after'])


def add_fwaas_subpolicy(obj, context, **kwargs):
    fwr_ass = {}
    for key in ['fwr_id', 'type']:
        fwr_ass.setdefault(key, kwargs.pop(key, None))
    fortinet_fwp = add_fwpolicy_to_head(obj, context, **kwargs)
    fwr_ass.setdefault('fortinet_pid', fortinet_fwp.id)
    add_record(
        obj, context, fortinet_db.Fortinet_FW_Rule_Association, **fwr_ass)


def delete_fwaas_subpolicy(obj, context, **kwargs):
    fortinet_db.Fortinet_FW_Rule_Association.delete_record(context, kwargs)
    if kwargs.get('fortinet_pid', None):
        delete_fwpolicy(obj, context, id=kwargs['fortinet_pid'])


def add_vip(obj, context, **kwargs):
    return add_by_name(obj, context, fortinet_db.Fortinet_Firewall_VIP,
                       resources.FirewallVip, **kwargs)


def delete_vip(obj, context, **kwargs):
    return delete_by_name(obj, context, fortinet_db.Fortinet_Firewall_VIP,
                          resources.FirewallVip, **kwargs)


def add_routerstatic(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_Static_Router
    record = add_record(obj, context, cls, **kwargs)
    kwargs.pop('subnet_id', None)
    res = add_resource_with_id(obj, context, record,
                               resources.RouterStatic, **kwargs)
    if not getattr(record, 'edit_id'):
        if res.get('results'):
            edit_id = res['results']['mkey']
        else:
            edit_id = res['mkey']
        cls.update_record(context, record, edit_id=edit_id)
    return record


def set_routerstatic(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_Static_Router
    if 'gateway' in kwargs:
        gateway = kwargs.pop('gateway', None)
        record = cls.query_one(context, **kwargs)
        if gateway == record.gateway:
            return
        elif record.edit_id:
            cls.update_record(context, record, gateway=gateway)
            kwargs.setdefault('id', record.edit_id)
            op(obj, context, resources.RouterStatic.set, **kwargs)


def delete_routerstatic(obj, context, **kwargs):
    return delete_by_id(obj, context,
                        fortinet_db.Fortinet_Static_Router,
                        resources.RouterStatic,
                        **kwargs)


def delete_routerstatics(obj, context, **kwargs):
    records = fortinet_db.query_records(context,
                                        fortinet_db.Fortinet_Static_Router,
                                        **kwargs)
    for record in records:
        delete_routerstatic(obj, context,
                            vdom=record.vdom,
                            edit_id=record.edit_id)


def add_addrgrp(obj, context, **kwargs):
    """
    :param context:
    :param kwargs:
     {
        "name": "addrgrp_osvdm1",
        "vdom": "osvdm1",
        "members": ["192.168.33.0"]
     }
    :return:
    """
    cls = fortinet_db.Fortinet_Firewall_Address
    records = fortinet_db.query_records(context, cls, group=kwargs['name'])
    for name in kwargs['members']:
        record = fortinet_db.query_record(context, cls,
                                          name=name, vdom=kwargs['vdom'])
        if not record.group:
            cls.update_record(context, record, group=kwargs['name'])
            # TODO(samsu): need to add a rollback action to taskmanager
        else:
            LOG.debug("The member %(record)s already joined a group",
                      {"record": record})
    for record in records:
        kwargs['members'].append(record.name)
    try:
        op(obj, context, resources.FirewallAddrgrp.get,
           name=kwargs['name'], vdom=kwargs['vdom'])
        # TODO(samsu): need to add a rollback action to taskmanager
        op(obj, context, resources.FirewallAddrgrp.set, **kwargs)
    except exception.ResourceNotFound:
        op(obj, context, resources.FirewallAddrgrp.add, **kwargs)


def delete_addrgrp(obj, context, **kwargs):
    """
    :param context: for database
    :param kwargs:
        example format
        {
            "name": "addrgrp_osvdm1",
            "vdom": "osvdm1",
            "members": ["192.168.10.0", "192.168.33.0"]
        }
        each member of members is the address name to be deleted in
        the specific firewall address group in FGT.
    """
    cls = fortinet_db.Fortinet_Firewall_Address
    records = fortinet_db.query_records(context, cls, group=kwargs['name'])
    if not records:
        LOG.debug("There is not any record in db")
        return

    members = [record.name for record in records
               if record.name not in kwargs['members']]
    if members:
        kwargs['members'] = members
        op(obj, context, resources.FirewallAddrgrp.set, **kwargs)
    else:
        delete_fwpolicy(obj, context, vdom=kwargs.get('vdom'),
                        srcintf='any', srcaddr=kwargs['name'],
                        dstintf='any', nat='disable')
        try:
            del kwargs['members']
            op(obj, context, resources.FirewallAddrgrp.delete, **kwargs)
        except Exception as e:
            resources.Exinfo(e)
    for record in records:
        if record.name not in members:
            record.update_record(context, record, group=None)


def add_vlink_intf(obj, context, vlink_vlan, vlink_ip):
    vdom = getattr(vlink_vlan, 'vdom')
    ipsubnet = netaddr.IPNetwork(vlink_ip.vlink_ip_subnet)
    if obj._fortigate.get('npu_available'):
        intf_ext, intf_int = 'npu0_vlink0', 'npu0_vlink1'
        add_vlanintf(obj, context,
                     name=vlink_vlan.inf_name_ext_vdom,
                     vdom=const.EXT_VDOM,
                     vlanid=vlink_vlan.vlanid,
                     interface=intf_ext,
                     ip=getip(ipsubnet, 1))
        add_vlanintf(obj, context,
                     name=vlink_vlan.inf_name_int_vdom,
                     vdom=vdom,
                     vlanid=vlink_vlan.vlanid,
                     interface=intf_int,
                     ip=getip(ipsubnet, 2))
    else:
        add_vdomlink(obj, context, vdom=vdom)
        op(obj, context, resources.VlanInterface.set,
           name=vlink_vlan.inf_name_ext_vdom,
           vdom=const.EXT_VDOM,
           ip=getip(ipsubnet, 1))
        op(obj, context, resources.VlanInterface.set,
           name=vlink_vlan.inf_name_int_vdom,
           vdom=vdom,
           ip=getip(ipsubnet, 2))


def get_vlink_intf(obj, context, **kwargs):
    vlink_vlan = fortinet_db.query_record(context,
                        fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                        **kwargs)
    if not vlink_vlan and kwargs.get('vdom', None):
        return add_vlink(obj, context, kwargs['vdom'])
    return (vlink_vlan.inf_name_int_vdom, vlink_vlan.inf_name_ext_vdom)


def delete_vlink_intf(obj, context, vlink_vlan):
    vdom = getattr(vlink_vlan, 'vdom')
    if obj._fortigate.get('npu_available'):
        delete_vlanintf(obj, context,
                        name=vlink_vlan.inf_name_int_vdom,
                        vdom=vdom)
        delete_vlanintf(obj, context,
                        name=vlink_vlan.inf_name_ext_vdom,
                        vdom=const.EXT_VDOM)
    else:
        delete_vdomlink(obj, context, vdom=vdom)


def add_vlink(obj, context, vdom):
    vlink_vlan = add_record(obj, context,
                        fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                        vdom=vdom)
    vlink_ip = add_record(obj, context,
                        fortinet_db.Fortinet_Vlink_IP_Allocation,
                        vdom=vdom,
                        vlink_id=vlink_vlan.id)
    if vlink_ip:
        add_vlink_intf(obj, context, vlink_vlan, vlink_ip)
        gateway_ip = get_ipaddr(netaddr.IPNetwork(vlink_ip.vlink_ip_subnet), 1)
        add_routerstatic(obj, context,
                         vdom=vdom,
                         dst=const.EXT_DEF_DST,
                         device=vlink_vlan.inf_name_int_vdom,
                         gateway=gateway_ip)
    return (vlink_vlan.inf_name_int_vdom, vlink_vlan.inf_name_ext_vdom)


def delete_vlink(obj, context, tenant_id):
    if fortinet_db.query_count(context, l3_db.Router,
                               tenant_id=tenant_id) or \
        fortinet_db.query_count(context, l3_db.FloatingIP,
                                tenant_id=tenant_id):
        db_routers = fortinet_db.query_records(context, l3_db.Router,
                                               tenant_id=tenant_id)
        db_fips = fortinet_db.query_records(context, l3_db.FloatingIP,
                                            tenant_id=tenant_id)
        LOG.debug("Keeping vlink, because existing data "
                  "db_routers: %(routers)s, db_fips: %(fips)s",
                 {'routers': db_routers, 'fips': db_fips})
        return False
    vdom = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                   tenant_id=tenant_id).vdom

    vlink_vlan = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                            vdom=vdom,
                            allocated=True)
    if not vlink_vlan:
        return False
    vlink_ip = fortinet_db.query_record(context,
                              fortinet_db.Fortinet_Vlink_IP_Allocation,
                              vdom=vdom,
                              vlink_id=vlink_vlan.id,
                              allocated=True)
    if not vlink_ip:
        return False
    """
    delete_fwpolicy(obj, context,
                    vdom=const.EXT_VDOM,
                    srcintf=vlink_vlan.inf_name_ext_vdom,
                    dstintf=obj._fortigate['ext_interface'],
                    nat='enable')"""
    gateway_ip = get_ipaddr(netaddr.IPNetwork(vlink_ip.vlink_ip_subnet), 1)
    delete_routerstatic(obj, context,
                        vdom=vdom,
                        dst=const.EXT_DEF_DST,
                        device=vlink_vlan.inf_name_int_vdom,
                        gateway=gateway_ip)
    delete_vlink_intf(obj, context, vlink_vlan)
    fortinet_db.delete_record(context,
                        fortinet_db.Fortinet_Vlink_IP_Allocation,
                        vdom=vdom,
                        vlink_id=vlink_vlan.id)
    fortinet_db.delete_record(context,
                        fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                        id=vlink_vlan.id)
    return True


def add_interface_ip(obj, context, **kwargs):
    """
    :param context:
    :param kwargs: example format as below
        {
            "ip": "10.160.37.20 255.255.255.0",
            "name": "port37",
            "vdom": "root"
        }
    :return:
    """
    inf_db = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_Interface,
                            name=kwargs.get('name'))
    if const.EXT_DEF_DST in getattr(inf_db, 'ip'):
        inf_db.update_record(context, inf_db, **kwargs)
        op(obj, context, resources.VlanInterface.set, **kwargs)
    else:
        records = fortinet_db.query_records(context,
                                  fortinet_db.Fortinet_Interface_subip,
                                  name=kwargs.get('name'))
        org_subips = [getattr(record, 'ip') for record in records]

        if kwargs.get('ip') in org_subips:
            return
        add_record(obj, context,
                   fortinet_db.Fortinet_Interface_subip, **kwargs)
        #org_subips.append(kwargs.get('ip'))
        #op(obj, context, resources.VlanInterface.set,
        #   name=kwargs.get('name'),
        #   vdom=kwargs.get('vdom'),
        #   secondaryips=org_subips)


def delete_interface_ip(obj, context, **kwargs):
    """
    :param context:
    :param kwargs: example format as below
        {
            "ip": "10.160.37.20 255.255.255.0",
            "name": "port37",
            "vdom": "root"
        }
    :return:
    """
    records = fortinet_db.query_records(context,
                                        fortinet_db.Fortinet_Interface_subip,
                                        name=kwargs.get('name'))
    org_subips = [getattr(record, 'ip') for record in records]
    if kwargs.get('ip') in org_subips:
        org_subips.remove(kwargs["ip"])
        #op(obj, context, resources.VlanInterface.set,
        #   name=kwargs.get('name'),
        #   vdom=kwargs.get('vdom'),
        #   secondaryips=org_subips)
        fortinet_db.delete_record(context,
                                  fortinet_db.Fortinet_Interface_subip,
                                  **kwargs)
    else:
        inf_db = fortinet_db.query_record(context,
                                          fortinet_db.Fortinet_Interface,
                                          **kwargs)
        if not inf_db:
            return
        if org_subips:
            kwargs['ip'] = org_subips.pop()
            op(obj, context, resources.VlanInterface.set,
               name=kwargs.get('name'),
               vdom=kwargs.get('vdom'),
               secondaryips=org_subips)
            fortinet_db.delete_record(context,
                                  fortinet_db.Fortinet_Interface_subip,
                                  **kwargs)
        else:
            kwargs['ip'] = const.EXT_DEF_DST

        op(obj, context, resources.VlanInterface.set, **kwargs)
        inf_db.update_record(context, inf_db, ip=kwargs['ip'])


def add_secondaryip(obj, context, **kwargs):
    """
    :param obj:
    :param context:
    :param kwargs:
            'name': vl_ext_xx,
            'vdom': const.EXT_VDOM,
            'ip': 'x.x.x.x x.x.x.x'
    :return:
    """
    records = fortinet_db.query_records(context,
                                fortinet_db.Fortinet_FloatingIP_Allocation,
                                vdom=kwargs['vdom'],
                                allocated=True)
    secondaryips = []
    for record in records:
        secondaryips.append(getip(record.ip_subnet, 1))

    if op(obj, context, resources.VlanInterface.set, name=kwargs['name'],
          vdom=const.EXT_VDOM, secondaryips=secondaryips):
        secondaryips.remove(kwargs['ip'])
        rollback = {
            'params': (
                obj._driver,
                {
                    'name': kwargs['name'],
                    'vdom': const.EXT_VDOM,
                    'secondaryips': secondaryips
                }
            ),
            'func': resources.VlanInterface.set
        }
        obj.task_manager.add(getid(context), **rollback)


def delete_secondaryip(obj, context, **kwargs):
    """
    :param obj:
    :param context:
    :param kwargs:
            'name': vl_ext_xx,
            'vdom': const.EXT_VDOM,
            'ip': 'x.x.x.x x.x.x.x'
    :return:
    """
    records = fortinet_db.query_records(context,
                                fortinet_db.Fortinet_FloatingIP_Allocation,
                                vdom=kwargs['vdom'],
                                allocated=True)
    secondaryips = []
    for record in records:
        secondaryip = getip(record.ip_subnet, 1)
        if secondaryip == kwargs.get('ip'):
            continue
        secondaryips.append(secondaryip)

    op(obj, context, resources.VlanInterface.set, name=kwargs['name'],
        vdom=kwargs['vdom'], secondaryips=secondaryips)


def set_ext_gw(obj, context, port):
    """
    :param context:
    :param port: example format
     port = {
        'status': 'DOWN',
        'binding:host_id': '',
        'allowed_address_pairs': [],
        'device_owner': 'network:router_gateway',
        'binding:profile': {},
        'fixed_ips': [{
            'subnet_id': u'09855a84-edfd-474d-b641-38a2bc63466a',
            'ip_address': u'10.160.37.111'
        }],
        'id': '6e68efc0-c0ca-40a2-a502-c2bf19304317',
        'security_groups': [],
        'device_id': u'8312d7a2-cae5-4e87-9c04-782c4a34bb8c',
        'name': '',
        'admin_state_up': True,
        'network_id': u'95eb736c-dd3b-4bf5-940a-8fa8e707a376',
        'tenant_id': '',
        'binding:vif_details': {},
        'binding:vnic_type': 'normal',
        'binding:vif_type': 'unbound',
        'mac_address': 'fa:16:3e:95:02:ab'
    }
    :return:
    """
    router_db = fortinet_db.query_record(context, l3_db.Router,
                                         id=port['device_id'])
    tenant_id = router_db.get('tenant_id', None)
    if not tenant_id:
        raise ValueError

    namespace = add_vdom(obj, context, tenant_id=tenant_id)
    #add_vlink(obj, context, namespace.vdom)
    vlink_db = fortinet_db.query_record(context,
                                fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                                vdom=namespace.vdom)

    ip_address = port['fixed_ips'][0]['ip_address']

    add_fwippool(obj, context, vdom=const.EXT_VDOM,
                 name=ip_address, startip=ip_address)

    add_fwpolicy(obj, context,
                 vdom=const.EXT_VDOM,
                 srcintf=vlink_db.inf_name_ext_vdom,
                 dstintf=obj._fortigate['ext_interface'],
                 poolname=ip_address)
    subnet_db = fortinet_db.query_record(context, models_v2.Subnet,
                                id=port['fixed_ips'][0]['subnet_id'])
    if subnet_db:
        netmask = netaddr.IPNetwork(subnet_db.cidr).netmask
        add_interface_ip(obj, context,
                         name=obj._fortigate['ext_interface'],
                         vdom=const.EXT_VDOM,
                         ip="%s %s" % (ip_address, netmask))


def clr_ext_gw(obj, context, port):
    ip_address = port['fixed_ips'][0]['ip_address']
    subnetv2_db = fortinet_db.query_record(context, models_v2.Subnet,
                                    id=port['fixed_ips'][0]['subnet_id'])
    netmask = netaddr.IPNetwork(subnetv2_db.cidr).netmask
    ip = "%s %s" % (ip_address, netmask)
    delete_interface_ip(obj, context,
                        name=obj._fortigate['ext_interface'],
                        vdom=const.EXT_VDOM,
                        ip=ip)

    delete_fwpolicy(obj, context, vdom=const.EXT_VDOM, poolname=ip_address)
    delete_fwippool(obj, context, vdom=const.EXT_VDOM, name=ip_address)
    #router_db = fortinet_db.query_record(context, l3_db.Router,
    #                                     id=port['device_id'])
    #tenant_id = router_db.get('tenant_id', None)
    #if tenant_id:
    #    #delete_vlink(obj, context, tenant_id=tenant_id)
    #    if (not [getattr(record, 'gw_port_id', None) for record in
    #             fortinet_db.query_records(context, l3_db.Router,
    #                                       tenant_id=tenant_id)
    #             if getattr(record, 'gw_port_id', None)] and
    #       not fortinet_db.query_count(context, models_v2.Network,
    #                                   tenant_id=tenant_id)):
    #        delete_vdom(obj, context, tenant_id=tenant_id)
