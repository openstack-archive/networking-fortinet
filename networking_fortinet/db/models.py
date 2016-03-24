# Copyright 2015 Fortinet, Inc.
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


"""Fortinet specific database schema/model."""

import copy
from neutron.db import model_base
from neutron.db import models_v2
from oslo_db import exception as os_db_exception
from oslo_log import log as logging
import six
import sqlalchemy as sa
from sqlalchemy.inspection import inspect
from sqlalchemy import orm

from networking_fortinet.common import constants as const


LOG = logging.getLogger(__name__)


OPS = ["ADD", "UPDATE", "DELETE", "QUERY"]


def add_record(context, cls, **kwargs):
    try:
        return cls.add_record(context, **kwargs)
    except os_db_exception.DBDuplicateEntry:
        pass
    return {}


def delete_record(context, cls, **kwargs):
    return cls.delete_record(context, kwargs)


def update_record(context, record, **kwargs):
    session = get_session(context)
    try:
        for key, value in six.iteritems(kwargs):
            if getattr(record, key, None) != value:
                setattr(record, key, value)
        with session.begin(subtransactions=True):
            session.add(record)
            return record
    except Exception as e:
        raise os_db_exception.DBError(e)


def query_record(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).first()


def query_records(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).all()


def query_count(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).count()


def get_session(context):
    return context.session if getattr(context, 'session', None) else context


def primary_keys(cls):
    """
    :param cls: Object or instance derived from the class ModelBase
                in the library sqlalchemy
    :return: list of primary keys
    """
    if not isinstance(cls, type):
        cls = cls.__class__
    return [key.name for key in inspect(cls).primary_key]


def db_query(cls, context, lockmode=False, **kwargs):
    """
    :param cls:
    :param context:
    :param kwargs:
    :return:
    """
    session = get_session(context)
    query = session.query(cls)
    if lockmode:
        query = query.with_lockmode('update')
    for key, value in six.iteritems(kwargs):
        kw = {key: value}
        query = query.filter_by(**kw)
    return query


class DBbase(object):
    @classmethod
    def init_records(cls, context, **kwargs):
        """Add records to be allocated into the table."""
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if not record:
                record = cls()
                for key, value in six.iteritems(kwargs):
                    if hasattr(record, key):
                        setattr(record, key, value)
                session.add(record)

    @classmethod
    def add_record(cls, context, **kwargs):
        """Add vlanid to be allocated into the table."""
        session = get_session(context)
        _kwargs = copy.copy(kwargs)
        for key in _kwargs:
            if not hasattr(cls, key):
                kwargs.pop(key, None)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if not record:
                record = cls()
                for key, value in six.iteritems(kwargs):
                    setattr(record, key, value)
                session.add(record)
                rollback = cls._prepare_rollback(context,
                                                 cls.delete_record,
                                                 **kwargs)
            else:
                rollback = {}
                #raise os_db_exception.DBDuplicateEntry
        ## TODO(samsu): kwargs would be better if only include class cls
        ## related primary keys
        return {'result': record, 'rollback': rollback}

    @staticmethod
    def update_record(context, record, **kwargs):
        """Add vlanid to be allocated into the table."""
        return update_record(context, record, **kwargs)

    @classmethod
    def delete_record(cls, context, kwargs):
        """
        Notes: kwargs is a dictionary as a variable, no wrapped as
        **kwargs because of the requirements of rollback process.
        Delete the record with the value of kwargs from the database,
        kwargs is a dictionary variable, here should not pass into a
        variable like **kwargs
        """
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, lockmode=True, **kwargs)
            if record:
                session.delete(record)
        return record

    @classmethod
    def query_one(cls, context, lockmode=False, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        query = db_query(cls, context, lockmode=lockmode, **kwargs)
        return query.first()

    @classmethod
    def query_all(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        query = db_query(cls, context, **kwargs)
        return query.all()

    @classmethod
    def query_count(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        query = db_query(cls, context, **kwargs)
        return query.count()

    @classmethod
    def query_like(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        session = get_session(context)
        query = session.query(cls)
        for key, value in six.iteritems(kwargs):
            if getattr(cls, key, None):
                query = query.filter(getattr(cls, key, None).like(value))
        return query.all()

    @staticmethod
    def _prepare_rollback(context, func, **kwargs):
        if not func:
            raise ValueError
        rollback = {
            'func': func,
            'params': (context, kwargs)
        }
        return rollback


class Fortinet_ML2_Namespace(model_base.BASEV2, DBbase):
    """Schema for Fortinet network."""
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    tenant_id = sa.Column(sa.String(36), primary_key=True)
    # For the name of vdom has the following restrictions:
    # only letters, numbers, "-" and "_" are allowed
    # no more than 11 characters are allowed
    # no spaces are allowed
    vdom = sa.Column(sa.String(11))

    @classmethod
    def add_record(cls, context, **kwargs):
        res = super(Fortinet_ML2_Namespace, cls).add_record(context, **kwargs)
        if res.get('rollback'):
            res['result']._allocate_vdom(context, res['result'])
        return res

    def _allocate_vdom(self, context, record):
        if not getattr(record, 'vdom'):
            vdom = const.PREFIX['vdom'] + str(record.id)
            self.update_record(context, record, vdom=vdom)
        return record.vdom


class Fortinet_ML2_Subnet(model_base.BASEV2, DBbase):
    """Schema to map subnet to Fortinet dhcp interface."""
    subnet_id = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    interface = sa.Column(sa.String(11), default=None)
    gateway = sa.Column(sa.String(32), default=None)
    netmask = sa.Column(sa.String(32), default=None)
    start_ip = sa.Column(sa.String(32), default=None)
    end_ip = sa.Column(sa.String(32), default=None)
    edit_id = sa.Column(sa.Integer)


class Fortinet_ML2_ReservedIP(model_base.BASEV2, DBbase):
    """Schema for Fortinet dhcp server reserved ip."""
    port_id = sa.Column(sa.String(36), primary_key=True)
    subnet_id = sa.Column(sa.String(36))
    mac = sa.Column(sa.String(32))
    ip = sa.Column(sa.String(32))
    vdom = sa.Column(sa.String(11))
    edit_id = sa.Column(sa.Integer)

    @classmethod
    def add_record(cls, context, **kwargs):
        res = super(Fortinet_ML2_ReservedIP, cls).add_record(context, **kwargs)
        if res.get('rollback'):
            cls._allocate_edit_id(context, res['result'])
        return res

    @classmethod
    def _allocate_edit_id(cls, context, record):
        if not getattr(record, 'edit_id'):
            last_record = (db_query(cls, context, subnet_id=record.subnet_id).
                           order_by(cls.edit_id.desc()).first())
            edit_id = last_record.edit_id + 1 if last_record.edit_id else 1
            record.update_record(context, record, edit_id=edit_id)
        return record.edit_id


class Fortinet_Static_Router(model_base.BASEV2, models_v2.HasId, DBbase):
    """Schema for Fortinet static router."""
    vdom = sa.Column(sa.String(11))
    subnet_id = sa.Column(sa.String(36))
    dst = sa.Column(sa.String(32))
    device = sa.Column(sa.String(32))
    gateway = sa.Column(sa.String(32))
    edit_id = sa.Column(sa.Integer)


class Fortinet_Vlink_Vlan_Allocation(model_base.BASEV2, models_v2.HasId,
                                     DBbase):
    """Schema for Fortinet vlink vlan interface."""
    vdom = sa.Column(sa.String(11))
    inf_name_int_vdom = sa.Column(sa.String(11))
    inf_name_ext_vdom = sa.Column(sa.String(11))
    vlanid = sa.Column(sa.Integer)
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)

    @staticmethod
    def reset():
        """
        set all value of keys in kwargs to the default value(None or False)
        """
        return {
            'vdom': None,
            'inf_name_int_vdom': None,
            'inf_name_ext_vdom': None,
            'allocated': False
        }

    @classmethod
    def add_record(cls, context, **kwargs):
        record = cls.query_one(context, **kwargs)
        if not record:
            kwargs.setdefault('allocated', True)
            if kwargs.get('vdom', None):
                kwargs.setdefault('inf_name_int_vdom',
                                  kwargs['vdom'] + const.POSTFIX['vint'])
                kwargs.setdefault('inf_name_ext_vdom',
                                  kwargs['vdom'] + const.POSTFIX['vext'])
            # TODO(samsu): if no vlanid needed, then it should able to add
            # a new record, consider to separate vlanid to a table.
            record = cls.query_one(context, lockmode=True, allocated=False)
            record.update_record(context, record, **kwargs)
            rollback = cls._prepare_rollback(context, cls.delete_record,
                                             **kwargs)
        else:
            rollback = {}
        ## need to check the attribute in the record whether updated
        ## # after update_record()
        return {'result': record, 'rollback': rollback}

    @classmethod
    def delete_record(cls, context, kwargs):
        """Delete vlanid to be allocated into the table."""
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if record:
                record.update_record(context, record, **cls.reset())
        return record


class Fortinet_Vlink_IP_Allocation(model_base.BASEV2, DBbase):
    """Schema for Fortinet vlink vlan interface."""
    vlink_ip_subnet = sa.Column(sa.String(32), primary_key=True)
    vdom = sa.Column(sa.String(11))
    vlink_id = sa.Column(sa.String(36),
                         sa.ForeignKey("fortinet_vlink_vlan_allocations.id",
                                       ondelete="CASCADE"), nullable=True)
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)

    @staticmethod
    def reset():
        """
        set all value of keys in kwargs to the default value(None or False)
        """
        return {
            'vdom': None,
            'vlanid': None,
            'allocated': False
        }

    @classmethod
    def add_record(cls, context, **kwargs):
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if not record:
                record = cls.query_one(context, lockmode=True, allocated=False)
                kwargs.setdefault('allocated', True)
                record.update_record(context, record, **kwargs)
                rollback = cls._prepare_rollback(context,
                                                 cls.delete_record,
                                                 **kwargs)
            else:
                rollback = {}
        ## need to check the attribute in the record whether updated
        ## # after update_record()
        return {'result': record, 'rollback': rollback}

    @classmethod
    def delete_record(cls, context, kwargs):
        """Delete vlanid to be allocated into the table."""
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if record:
                record.update_record(context, record, **cls.reset())
        return record


class Fortinet_Vdom_Vlink(model_base.BASEV2, DBbase):
    """Schema for Fortinet vlink vlan interface."""
    name = sa.Column(sa.String(11), primary_key=True)
    vdom = sa.Column(sa.String(11), primary_key=True)

    @classmethod
    def add_record(cls, context, **kwargs):
        if kwargs.get('vdom', None):
            kwargs.setdefault('name', kwargs['vdom'] + const.POSTFIX['vdlink'])
        return super(Fortinet_Vdom_Vlink, cls).add_record(context, **kwargs)


class Fortinet_Firewall_Policy(model_base.BASEV2, models_v2.HasId, DBbase):
    """Schema for Fortinet firewall policy."""
    __tablename__ = 'fortinet_firewall_policies'
    vdom = sa.Column(sa.String(11))
    srcintf = sa.Column(sa.String(11), default="any")
    dstintf = sa.Column(sa.String(11), default="any")
    srcaddr = sa.Column(sa.String(40), default="all")
    dstaddr = sa.Column(sa.String(40), default="all")
    poolname = sa.Column(sa.String(32), default=None)
    nat = sa.Column(sa.String(7), default="disable")
    action = sa.Column(sa.String(11), default="accept")
    service = sa.Column(sa.String(36), default="ALL")
    match_vip = sa.Column(sa.String(7), default="disable")
    status = sa.Column(sa.String(7), default="enable")
    av_profile = sa.Column(sa.String(35), default=None)
    webfilter_profile = sa.Column(sa.String(35), default=None)
    ips_sensor = sa.Column(sa.String(35), default=None)
    application_list = sa.Column(sa.String(35), default=None)
    ssl_ssh_profile = sa.Column(sa.String(35), default=None)
    # comments(max 1023 in fortigate) to save firewall rule name (max 255)
    comments = sa.Column(sa.String(255), default=None)
    edit_id = sa.Column(sa.Integer)


class Fortinet_FloatingIP_Allocation(model_base.BASEV2, DBbase):
    """Schema for Fortinet vlink vlan interface.
    ip_subnet: it is a network with 30 bits network, there
    are two ips available, the smaller one will be allocated
    to the interface of the external network vdom and the
    bigger one will be allocated to the interface of related
    tenant network vdom.
    """
    ip_subnet = sa.Column(sa.String(32), primary_key=True)
    floating_ip_address = sa.Column(sa.String(36))
    vdom = sa.Column(sa.String(11))
    vip_name = sa.Column(sa.String(50))
    ## secondary_ip = sa.Column(sa.String(50), default=None)
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)
    ## TODO(samsu): delete the field bound

    @staticmethod
    def reset():
        """
        set all value of keys in kwargs to the default value(None or False)
        """
        return {
            'floating_ip_address': None,
            'vdom': None,
            'vip_name': None,
            'allocated': False
        }

    @classmethod
    def add_record(cls, context, **kwargs):
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if not record:
                record = cls.query_one(context, lockmode=True, allocated=False)
                kwargs.setdefault('allocated', True)
                record.update_record(context, record, **kwargs)
                rollback = cls._prepare_rollback(context,
                                                 cls.delete_record,
                                                 **kwargs)
            else:
                rollback = {}
        ## need to check the attribute in the record whether updated
        ## # after update_record()
        return {'result': record, 'rollback': rollback}

    @classmethod
    def delete_record(cls, context, kwargs):
        """Delete vlanid to be allocated into the table."""
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query_one(context, **kwargs)
            if record:
                record.update_record(context, record, **cls.reset())
        return record


class Fortinet_Firewall_VIP(model_base.BASEV2, DBbase):
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11), primary_key=True)
    extip = sa.Column(sa.String(32))
    extintf = sa.Column(sa.String(32))
    mappedip = sa.Column(sa.String(32), default=None)


class Fortinet_Firewall_IPPool(model_base.BASEV2, DBbase):
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    startip = sa.Column(sa.String(32))
    endip = sa.Column(sa.String(32))
    type = sa.Column(sa.String(32), default="one-to-one")
    comments = sa.Column(sa.String(32), default=None)

    @classmethod
    def add_record(cls, context, **kwargs):
        kwargs.setdefault('endip', kwargs.get('startip', None))
        return super(Fortinet_Firewall_IPPool, cls).add_record(context,
                                                               **kwargs)


class Fortinet_Firewall_Address(model_base.BASEV2, DBbase):
    __tablename__ = 'fortinet_firewall_addresses'
    name = sa.Column(sa.String(40), primary_key=True)
    vdom = sa.Column(sa.String(11), primary_key=True)
    subnet = sa.Column(sa.String(32))
    associated_interface = sa.Column(sa.String(11), default=None)
    group = sa.Column(sa.String(32), default=None)


class Fortinet_Firewall_Service(model_base.BASEV2, DBbase):
    #__tablename__ = 'fortinet_firewall_services'
    # service name <- firewall_rule id
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11), primary_key=True)


class Fortinet_Interface(model_base.BASEV2, DBbase):
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    vlanid = sa.Column(sa.Integer)
    interface = sa.Column(sa.String(11), default=None)
    type = sa.Column(sa.String(32), default=None)
    ip = sa.Column(sa.String(32), default=const.EXT_DEF_DST)
    secondary_ip = sa.Column(sa.String(11), default="enable")
    alias = sa.Column(sa.String(32), default=None)


class Fortinet_Interface_subip(model_base.BASEV2, DBbase):
    ip = sa.Column(sa.String(32), primary_key=True)
    name = sa.Column(sa.String(11), default=None)
    vdom = sa.Column(sa.String(11))


class Fortinet_FW_Rule_Association(model_base.BASEV2, DBbase):
    fwr_id = sa.Column(sa.String(36),
        sa.ForeignKey('firewall_rules.id', ondelete="CASCADE"),
        primary_key=True)
    fortinet_pid = sa.Column(sa.String(36),
        sa.ForeignKey('fortinet_firewall_policies.id', ondelete="CASCADE"),
        primary_key=True)
    type = sa.Column(sa.String(36), default=None)
    floatingip_id = sa.Column(sa.String(36),
        sa.ForeignKey('floatingips.id', ondelete="CASCADE"), nullable=True)
    fortinet_policy = orm.relationship(
        "Fortinet_Firewall_Policy", backref='fortinet_fw_rule_association')
