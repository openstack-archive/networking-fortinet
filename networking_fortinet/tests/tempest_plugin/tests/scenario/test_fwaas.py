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

import testscenarios

from tempest import config
from tempest.lib import decorators
from tempest import test

from networking_fortinet.tests.tempest_plugin.tests.scenario import base

CONF = config.CONF

load_tests = testscenarios.load_tests_apply_scenarios


class TestFortigateFWaaS(base.FWaaSScenarioTest):
    scenarios = [
        # ('without router insersion', {
        #     'router_insertion': False,
        # }),
        ('with router insersion', {
            'router_insertion': True,
        }),
    ]

    @classmethod
    def skip_checks(cls):
        super(TestFortigateFWaaS, cls).skip_checks()
        if not CONF.network.public_network_id:
            msg = ('Either project_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)

    def setUp(self):
        super(TestFortigateFWaaS, self).setUp()
        required_exts = ['fwaas', 'security-group', 'router']
        if self.router_insertion:
            required_exts.append('fwaasrouterinsertion')
        for ext in required_exts:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s Extension not enabled." % ext
                raise self.skipException(msg)
        self._router_ids = None

    def _create_server(self, network, security_group=None):
        keys = self.create_keypair()
        kwargs = {}
        if security_group is not None:
            kwargs['security_groups'] = [{'name': security_group['name']}]
        server = self.create_server(
            key_name=keys['name'],
            networks=[{'uuid': network['id']}],
            wait_until='ACTIVE',
            **kwargs)
        return server, keys

    def _create_firewall(self, **kwargs):
        if self._router_ids is not None:
            kwargs['router_ids'] = self._router_ids
        return self.create_firewall(**kwargs)

    def _empty_policy(self, **kwargs):
        # NOTE(yamamoto): an empty policy would deny all
        fw_policy = self.create_firewall_policy(firewall_rules=[])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
        }

    def _empty_existing_policy(self, ctx):
        self.firewall_policies_client.update_firewall_policy(
            firewall_policy_id=ctx['fw_policy']['id'], firewall_rules=[])

    def _update_policy_with_allow_rule(self, ctx):
        rules = [
            self.create_firewall_rule(
                destination_ip_address=ctx['server1_fixed_ip'],
                action="allow"),
            self.create_firewall_rule(
                source_ip_address=ctx['server1_fixed_ip'],
                action="allow"),
        ]
        rule_ids = [r['id'] for r in rules]
        self.firewall_policies_client.update_firewall_policy(
            firewall_policy_id=ctx['fw_policy']['id'],
            firewall_rules=rule_ids)
        for rule_id in rule_ids:
            self.addCleanup(
                self._remove_rule_and_wait,
                firewall_id=ctx['fw']['id'],
                firewall_policy_id=ctx['fw_policy']['id'],
                firewall_rule_id=rule_id)

    def _all_disabled_rules(self, **kwargs):
        # NOTE(yamamoto): a policy whose rules are all disabled would deny all
        fw_rule = self.create_firewall_rule(action="allow", enabled=False)
        fw_policy = self.create_firewall_policy(firewall_rules=[fw_rule['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _block_ip(self, server1_fixed_ip, **kwargs):
        rules = [
            # NOTE(yamamoto): The filtering is taken place after
            # destination ip is rewritten to fixed-ip.
            self.create_firewall_rule(destination_ip_address=server1_fixed_ip,
                                      action="deny"),
            #self.create_firewall_rule(destination_ip_address=server2_fixed_ip,
            #                          action="deny"),
            self.create_firewall_rule(action="allow"),
        ]
        rule_ids = [r['id'] for r in rules]
        fw_policy = self.create_firewall_policy(firewall_rules=rule_ids)
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'server1_fixed_ip': server1_fixed_ip,
            #'server2_fixed_ip': server2_fixed_ip,
        }

    def _block_subnet(self, subnet1, **kwargs):
        rules = [
            self.create_firewall_rule(destination_ip_address=subnet1["cidr"],
                                      action="deny"),
            self.create_firewall_rule(action="allow"),
        ]
        rule_ids = [r['id'] for r in rules]
        fw_policy = self.create_firewall_policy(firewall_rules=rule_ids)
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'subnet1': subnet1["cidr"],
        }

    def _block_icmp(self, **kwargs):
        fw_rule = self.create_firewall_rule(
            protocol="icmp",
            action="deny")
        fw_rule_allow = self.create_firewall_rule(
            action="allow")
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule['id'], fw_rule_allow['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _block_ssh(self, **kwargs):
        fw_rule = self.create_firewall_rule(
            protocol="tcp",
            destination_port="22",
            action="deny")
        fw_rule_allow = self.create_firewall_rule(
            action="allow")
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule['id'], fw_rule_allow['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _block_all_with_default_allow(self, **kwargs):
        fw_rule = self.create_firewall_rule(
            action="deny")
        fw_rule_allow = self.create_firewall_rule(
            action="allow")
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule['id'], fw_rule_allow['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _admin_disable(self, **kwargs):
        # NOTE(yamamoto): A firewall with admin_state_up=False would block all
        fw_rule = self.create_firewall_rule(action="allow")
        fw_policy = self.create_firewall_policy(firewall_rules=[fw_rule['id']])
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'],
                                  admin_state_up=False)
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _allow_ssh_and_icmp(self, ctx):
        fw_ssh_rule = self.create_firewall_rule(
            protocol="tcp",
            destination_port=22,
            action="allow")
        fw_icmp_rule = self.create_firewall_rule(
            protocol="icmp",
            action="allow")
        for rule in [fw_ssh_rule, fw_icmp_rule]:
            self.firewall_policies_client.insert_firewall_rule_in_policy(
                firewall_policy_id=ctx['fw_policy']['id'],
                firewall_rule_id=rule['id'],
                insert_before=ctx['fw_rule']['id'])
            self.addCleanup(
                self._remove_rule_and_wait,
                firewall_id=ctx['fw']['id'],
                firewall_policy_id=ctx['fw_policy']['id'],
                firewall_rule_id=rule['id'])
            self._wait_firewall_ready(ctx['fw']['id'])

    def _remove_rule_and_wait(self, firewall_id, firewall_policy_id,
                              firewall_rule_id):
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id)
        self._wait_firewall_ready(firewall_id)

    def _delete_fw(self, ctx):
        self.delete_firewall_and_wait(ctx['fw']['id'])

    def _set_admin_up(self, firewall_id, up):
        self.firewalls_client.update_firewall(firewall_id=firewall_id,
                                              admin_state_up=up)
        self._wait_firewall_ready(firewall_id=firewall_id)

    def _admin_enable(self, ctx):
        self._set_admin_up(ctx['fw']['id'], up=True)

    def _remove_rule(self, ctx):
        self._remove_rule_and_wait(
            firewall_id=ctx['fw']['id'],
            firewall_policy_id=ctx['fw_policy']['id'],
            firewall_rule_id=ctx['fw_rule']['id'])

    def _disable_rule(self, ctx):
        self.firewall_rules_client.update_firewall_rule(
            firewall_rule_id=ctx['fw_rule']['id'],
            enabled=False)
        self._wait_firewall_ready(ctx['fw']['id'])

    def _remove_router_from_fw(self, ctx):
        self.firewalls_client.update_firewall(firewall_id=ctx['fw']['id'],
                                              router_ids=[])
        self._wait_firewall_ready(ctx['fw']['id'])

    def _update_block_ssh_rule_by_port(self, ctx):
        self.firewall_rules_client.update_firewall_rule(
            firewall_rule_id=ctx['fw_rule']['id'],
            destination_port="23:25")

    def _update_block_ssh_rule_by_action(self, ctx):
        self.firewall_rules_client.update_firewall_rule(
            firewall_rule_id=ctx['fw_rule']['id'],
            action="allow")

    def _update_block_ssh_rule_by_proto(self, ctx):
        self.firewall_rules_client.update_firewall_rule(
            firewall_rule_id=ctx['fw_rule']['id'],
            protocol="udp")

    def _allow_ip(self, ctx):
        self._delete_fw(ctx)
        server1_fixed_ip = ctx['server1_fixed_ip']
        #server2_fixed_ip = ctx['server2_fixed_ip']
        rules = [
            # NOTE(yamamoto): The filtering is taken place after
            # destination ip is rewritten to fixed-ip.
            # The return traffic should be allowed regardless
            # of firewall rules.
            self.create_firewall_rule(
                destination_ip_address=server1_fixed_ip,
                action="allow"),
            #self.create_firewall_rule(
            #    destination_ip_address=server2_fixed_ip,
            #    action="allow"),
        ]
        rule_ids = [r['id'] for r in rules]
        fw_policy = self.create_firewall_policy(firewall_rules=rule_ids)
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])

    def _allow_subnet(self, ctx):
        self._delete_fw(ctx)
        subnet1 = ctx['subnet1']
        rules = [
            self.create_firewall_rule(
                destination_ip_address=subnet1,
                action="allow"),
        ]
        rule_ids = [r['id'] for r in rules]
        fw_policy = self.create_firewall_policy(firewall_rules=rule_ids)
        fw = self._create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])

    def _confirm_allowed(self, **kwargs):
        self.check_connectivity(check_reverse_icmp_ip=self._public_gateway_ip,
                                check_reverse_curl=False,
                                **kwargs)

    def _confirm_allow_novirus(self, **kwargs):
        self.check_connectivity(check_reverse_icmp_ip=self._public_gateway_ip,
                                check_reverse_curl=True,
                                **kwargs)

    def _confirm_allowed_oneway(self, **kwargs):
        # Can ping and ssh, but can't ping back to the public gateway.
        # Same as _confirm_allowed if _public_gateway_ip is None.
        self.check_connectivity(check_reverse_icmp_ip=self._public_gateway_ip,
                                should_reverse_connect=False, **kwargs)

    def _confirm_blocked(self, **kwargs):
        self.check_connectivity(should_connect=False, **kwargs)

    def _confirm_icmp_blocked_but_tcp(self, **kwargs):
        self.check_connectivity(should_connect=False, check_ssh=False,
                                **kwargs)
        self.check_connectivity(check_icmp=False, **kwargs)

    def _confirm_ssh_blocked(self, **kwargs):
        self.check_connectivity(check_ssh=False, **kwargs)
        self.check_connectivity(should_connect=False, check_ssh=True,
                                check_icmp=False, **kwargs)

    def _create_topology(self):
        """Create a topology for testing

        +--------+             +-----------+
        |"server"|             | "subnet"  |
        |   VM   +-------------+ "network" |
        +--------+             +----+------+
                                    |
                                    | router interface port
                               +----+-----+
                               | "router" |
                               +----+-----+
                                    | router gateway port
                                    |
                                    |
                               +----+------------------+
                               | existing network      |
                               | ("public_network_id") |
                               +-----------------------+
        """
        public_network_id = CONF.network.public_network_id
        network, subnet, router = self.create_networks()
        security_group = self._create_security_group()
        server, keys = self._create_server(network,
                                           security_group=security_group)
        private_key = keys['private_key']
        server_floating_ip = self.create_floating_ip(server, public_network_id)
        fixed_ip = server['addresses'].values()[0][0]['addr']
        floating_ip = server_floating_ip['floating_ip_address']
        return fixed_ip, floating_ip, subnet, private_key, router

    def _get_public_gateway_ip(self):
        self._public_gateway_ip = None
        router = self._get_router()
        ext_gw_info = router['external_gateway_info']
        ext_fixed_ips = ext_gw_info['external_fixed_ips']
        for ip in ext_fixed_ips:
            subnet_id = ip['subnet_id']
            res = self.admin_manager.subnets_client.show_subnet(subnet_id)
            subnet = res['subnet']
            # REVISIT(yamamoto): IPv4 assumption
            if subnet['ip_version'] == 4:
                self._public_gateway_ip = subnet['gateway_ip']
                return

    def _test_firewall_basic(self, block, allow=None,
                             confirm_allowed=None, confirm_blocked=None):
        if allow is None:
            allow = self._delete_fw
        if confirm_allowed is None:
            confirm_allowed = self._confirm_allowed
        if confirm_blocked is None:
            confirm_blocked = self._confirm_blocked
        ssh_login = CONF.validation.image_ssh_user

        if self.router_insertion and CONF.network.public_router_id:
            # NOTE(yamamoto): If public_router_id is configured
            # router1 and router2 will be the same router.
            msg = "This test assumes no public_router_id configured"
            raise self.skipException(msg)

        (server1_fixed_ip, server1_floating_ip, subnet1, private_key1,
         router1) = self._create_topology()
        #server2_fixed_ip, server2_floating_ip, private_key2, router2 = \
        #    self._create_topology()
        self._get_public_gateway_ip()
        if self.router_insertion:
            # Specify the router when creating a firewall and ensures that
            # the other router (router2) is not affected by the firewall
            self._router_ids = [router1['id']]
        #    confirm_allowed2 = confirm_allowed
        #    confirm_blocked2 = confirm_blocked
        else:
            # Without router insertion, all routers should be affected
            # equally
            pass
        #    confirm_allowed2 = confirm_allowed
        #    confirm_blocked2 = confirm_blocked
        self.check_connectivity(ip_address=server1_floating_ip,
                                username=ssh_login,
                                private_key=private_key1)
        #self.check_connectivity(ip_address=server2_floating_ip,
        #                        username=ssh_login,
        #                        private_key=private_key2)
        ctx = block(server1_fixed_ip=server1_fixed_ip,
                    server1_floating_ip=server1_floating_ip,
                    subnet1=subnet1)
        #            server2_fixed_ip=server2_fixed_ip,
        #            server2_floating_ip=server2_floating_ip)
        confirm_blocked(ip_address=server1_floating_ip, username=ssh_login,
                        private_key=private_key1)
        #confirm_blocked2(ip_address=server2_floating_ip, username=ssh_login,
        #                 private_key=private_key2)
        allow(ctx)
        confirm_allowed(ip_address=server1_floating_ip, username=ssh_login,
                        private_key=private_key1)
        #confirm_allowed2(ip_address=server2_floating_ip, username=ssh_login,
        #                 private_key=private_key2)

    @test.idempotent_id('5b5f57bb-e3ca-4246-9174-bb5fe9298c5f')
    def test_firewall_block_ip(self):
        self._test_firewall_basic(block=self._block_ip, allow=self._allow_ip,
                                  confirm_allowed=self._confirm_allowed_oneway)

    @test.idempotent_id('5b5f57bb-e3ca-4246-9174-bb5fe9298c5e')
    def test_firewall_block_subnet(self):
        self._test_firewall_basic(block=self._block_subnet,
                                  allow=self._allow_subnet,
                                  confirm_allowed=self._confirm_allowed_oneway)

    @test.idempotent_id('22e23dd5-c00c-4510-87ea-4874c705a45f')
    def test_firewall_block_icmp(self):
        self._test_firewall_basic(
            block=self._block_icmp,
            confirm_blocked=self._confirm_icmp_blocked_but_tcp)

    @test.idempotent_id('5db47fa0-d3e1-49f5-b6ca-6e0fa6c397c6')
    def test_firewall_insert_rule(self):
        self._test_firewall_basic(
            block=self._block_icmp,
            allow=self._allow_ssh_and_icmp,
            confirm_blocked=self._confirm_icmp_blocked_but_tcp)

    @test.idempotent_id('20466b39-e356-4e58-bb8e-199d1172eb53')
    def test_firewall_remove_rule(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._remove_rule,
                                  confirm_allowed=self._confirm_allow_novirus)

    @decorators.skip_because(bug="0363573")
    @test.idempotent_id('deb5874a-cc43-468e-9ac6-42b9e8a767fd')
    def test_firewall_disable_rule(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._disable_rule)

    @test.idempotent_id('18b085f2-c63a-46b4-8764-d0e8f803ede1')
    def test_firewall_remove_router_from_fw(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._remove_router_from_fw)

    @test.idempotent_id('18b085f2-c63a-46b4-8764-d0e8f803ede2')
    def test_firewall_update_ssh_policy_by_port(self):
        self._test_firewall_basic(block=self._block_ssh,
                                  allow=self._update_block_ssh_rule_by_port,
                                  confirm_blocked=self._confirm_ssh_blocked,
                                  confirm_allowed=self._confirm_allow_novirus)

    @test.idempotent_id('18b085f2-c63a-46b4-8764-d0e8f803ede3')
    def test_firewall_update_ssh_policy_by_action(self):
        self._test_firewall_basic(block=self._block_ssh,
                                  allow=self._update_block_ssh_rule_by_action,
                                  confirm_blocked=self._confirm_ssh_blocked,
                                  confirm_allowed=self._confirm_allow_novirus)

    @test.idempotent_id('18b085f2-c63a-46b4-8764-d0e8f803ede4')
    def test_firewall_update_ssh_policy_by_proto(self):
        self._test_firewall_basic(block=self._block_ssh,
                                  allow=self._update_block_ssh_rule_by_proto,
                                  confirm_blocked=self._confirm_ssh_blocked,
                                  confirm_allowed=self._confirm_allow_novirus)

    @test.idempotent_id('18b085f2-c63a-46b4-8764-d0e8f803ede5')
    def test_firewall_empty_policy(self):
        if not self._default_allow():
            self._test_firewall_basic(block=self._empty_policy)
        else:
            self._test_firewall_basic(block=self._block_ip,
                                      allow=self._empty_existing_policy)

    @test.idempotent_id('18b085f2-c63a-46b4-8764-d0e8f803ede6')
    def test_firewall_update_policy_with_new_rule(self):
        self._test_firewall_basic(block=self._block_ip,
                                  allow=self._update_policy_with_allow_rule,
                                  confirm_allowed=self._confirm_allow_novirus)

    @decorators.skip_because(bug="0363573")
    @test.idempotent_id('30174d2a-820b-4939-85e2-49c735f7de0c')
    def test_firewall_all_disabled_rules(self):
        self._test_firewall_basic(block=self._all_disabled_rules)

    @decorators.skip_because(bug="0363573")
    @test.idempotent_id('2233ade8-266c-4781-b052-fc0be93baa93')
    def test_firewall_admin_disable(self):
        self._test_firewall_basic(block=self._admin_disable,
                                  allow=self._admin_enable)
