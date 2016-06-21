# Copyright (c) 2015 Midokura SARL
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

from oslo_config import cfg

from tempest import exceptions
from tempest.lib.common import ssh
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager

from networking_fortinet.tests.tempest_plugin.tests import fwaas_client

CONF = cfg.CONF


class FWaaSScenarioTest(fwaas_client.FWaaSClientMixin,
                        manager.NetworkScenarioTest):

    def check_connectivity(self, ip_address, username=None, private_key=None,
                           should_connect=True,
                           check_icmp=True, check_ssh=True,
                           check_reverse_icmp_ip=None,
                           should_reverse_connect=True,
                           check_reverse_curl=False):
        # if default allow is enabled as default by fgt fwaas, reverse
        # connection should always be available.
        if self._default_allow():
            should_reverse_connect = True
        if should_connect:
            msg = "Timed out waiting for %s to become reachable" % ip_address
        else:
            msg = "ip address %s is reachable" % ip_address
        if check_icmp:
            ok = self.ping_ip_address(ip_address,
                                      should_succeed=should_connect)
            self.assertTrue(ok, msg=msg)
        if check_ssh:
            connect_timeout = CONF.validation.connect_timeout
            kwargs = {}
            if not should_connect:
                # Use a shorter timeout for negative case
                kwargs['timeout'] = 1
            try:
                client = ssh.Client(ip_address, username, pkey=private_key,
                                    channel_timeout=connect_timeout,
                                    **kwargs)
                client.test_connection_auth()
                self.assertTrue(should_connect, "Unexpectedly reachable")
                if check_reverse_icmp_ip:
                    cmd = 'ping -c1 -w2 %s' % check_reverse_icmp_ip
                    try:
                        client.exec_command(cmd)
                        self.assertTrue(should_reverse_connect,
                                        "Unexpectedly reachable (reverse)")
                    except lib_exc.SSHExecCommandFailed:
                        if should_reverse_connect:
                            raise
                    if check_reverse_curl:
                        cmd1 = 'curl http://httpstat.us/200 |grep "200 OK"'
                        cmd2 = 'curl http://www.eicar.org/download/eicar.com|\
                                grep EICAR-STANDARD-ANTIVIRUS-TEST-FILE'
                        try:
                            client.exec_command(cmd1)
                            self.assertTrue(should_reverse_connect,
                                            "Unexpectedly reachable (reverse)")
                        except lib_exc.SSHExecCommandFailed:
                            if should_reverse_connect:
                                raise
                        # test virus file download should be blocked by default
                        # security profile enabled.
                        try:
                            client.exec_command(cmd2)
                            self.assertFalse(should_reverse_connect,
                                            "Unexpectedly reachable (reverse)")
                            raise
                        except lib_exc.SSHExecCommandFailed:
                            if should_reverse_connect:
                                pass
            except lib_exc.SSHTimeout:
                if should_connect:
                    raise

    def create_networks(self, networks_client=None,
                        routers_client=None, subnets_client=None,
                        tenant_id=None, dns_nameservers=None):
        """Create a network with a subnet connected to a router.
        The baremetal driver is a special case since all nodes are
        on the same shared network.
        :param client: network client to create resources with.
        :param tenant_id: id of tenant to create resources in.
        :param dns_nameservers: list of dns servers to send to subnet.
        :returns: network, subnet, router
        """
        if CONF.baremetal.driver_enabled:
            # NOTE(Shrews): This exception is for environments where tenant
            # credential isolation is available, but network separation is
            # not (the current baremetal case). Likely can be removed when
            # test account mgmt is reworked:
            # https://blueprints.launchpad.net/tempest/+spec/test-accounts
            if not CONF.compute.fixed_network_name:
                m = 'fixed_network_name must be specified in config'
                raise exceptions.InvalidConfiguration(m)
            network = self._get_network_by_name(
                CONF.compute.fixed_network_name)
            router = None
            subnet = None
        else:
            network = self._create_network(
                networks_client=networks_client,
                tenant_id=tenant_id)
            router = self._get_router(client=routers_client,
                                      tenant_id=tenant_id)

            subnet_kwargs = dict(network=network,
                                 subnets_client=subnets_client,
                                 routers_client=routers_client)
            # use explicit check because empty list is a valid option
            if dns_nameservers is not None:
                subnet_kwargs['dns_nameservers'] = dns_nameservers
            subnet = self._create_subnet(**subnet_kwargs)
            if not routers_client:
                routers_client = self.routers_client
            routers_client.add_router_interface(router['id'],
                                                subnet_id=subnet['id'])
            # save a cleanup job to remove this association between
            # router and subnet
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            routers_client.remove_router_interface,
                            router['id'], subnet_id=subnet['id'])
        return network, subnet, router

    def _get_router(self, client=None, tenant_id=None):
        """Retrieve a router for the given tenant id.
        If a public router has been configured, it will be returned.
        If a public router has not been configured, but a public
        network has, a tenant router will be created and returned that
        routes traffic to the public network.
        """
        if not client:
            client = self.routers_client
        if not tenant_id:
            tenant_id = client.tenant_id
        router_id = CONF.network.public_router_id
        network_id = CONF.network.public_network_id
        if router_id:
            body = client.show_router(router_id)
            return body['router']
        elif network_id:
            # fortigate plugin only allow one router per tenant, so if
            # a router already exists, use it.
            routers_list = client.list_routers(tenant_id=tenant_id)
            if len(routers_list['routers']) == 1:
                router = routers_list['routers'][0]
            else:
                router = self._create_router(client, tenant_id)
            kwargs = {'external_gateway_info': dict(network_id=network_id)}
            router = client.update_router(router['id'], **kwargs)['router']
            return router
        else:
            raise Exception("Neither of 'public_router_id' or "
                            "'public_network_id' has been defined.")

    def _default_allow(self):
        if CONF.fortigate.enable_default_fwrule:
            return False
        else:
            return True
