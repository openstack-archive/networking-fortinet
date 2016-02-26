# Copyright 2014 NEC Corporation. All rights reserved.
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

import six

from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test

from networking_fortinet.tests.tempest_plugin.tests.api import base

CONF = config.CONF


class FortigateFWaaSExtensionTestJSON(base.BaseFWaaSTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        List firewall rules
        Create firewall rule
        Update firewall rule
        Delete firewall rule
        Show firewall rule
        List firewall policies
        Create firewall policy
        Update firewall policy
        Insert firewall rule to policy
        Remove firewall rule from policy
        Insert firewall rule after/before rule in policy
        Update firewall policy audited attribute
        Delete firewall policy
        Show firewall policy
        List firewall
        Create firewall
        Update firewall
        Delete firewall
        Show firewall
    """

    @classmethod
    def resource_setup(cls):
        super(FortigateFWaaSExtensionTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('fwaas', 'network'):
            msg = "FWaaS Extension not enabled."
            raise cls.skipException(msg)

    def setUp(self):
        super(FortigateFWaaSExtensionTestJSON, self).setUp()
        self.fw_rule = self.create_firewall_rule(action="allow",
                                                 protocol="tcp")
        self.fw_policy = self.create_firewall_policy()

    def _try_delete_policy(self, policy_id):
        # delete policy, if it exists
        try:
            self.firewall_policies_client.delete_firewall_policy(policy_id)
        # if policy is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_rule(self, rule_id):
        # delete rule, if it exists
        try:
            self.firewall_rules_client.delete_firewall_rule(rule_id)
        # if rule is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_firewall(self, fw_id):
        # delete firewall, if it exists
        try:
            self.firewalls_client.delete_firewall(fw_id)
        # if firewall is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

        self.firewalls_client.wait_for_resource_deletion(fw_id)

    def _try_delete_router(self, rt):
        # delete router, if it exists
        try:
            self.delete_router(rt)
        except lib_exc.NotFound:
            pass

    def _wait_until_ready(self, fw_id):
        target_states = ('ACTIVE', 'CREATED')

        def _wait():
            firewall = self.firewalls_client.show_firewall(fw_id)
            firewall = firewall['firewall']
            return firewall['status'] in target_states

        if not test.call_until_true(_wait, CONF.network.build_timeout,
                                    CONF.network.build_interval):
            m = ("Timed out waiting for firewall %s to reach %s state(s)" %
                 (fw_id, target_states))
            raise exceptions.TimeoutException(m)

    @test.idempotent_id('60a20691-8496-4a2d-a54c-0d5145592624')
    def test_list_firewall_rules(self):
        # List firewall rules
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        fw_rules = fw_rules['firewall_rules']
        self.assertIn((self.fw_rule['id'],
                       self.fw_rule['name'],
                       self.fw_rule['action'],
                       self.fw_rule['protocol'],
                       self.fw_rule['ip_version'],
                       self.fw_rule['enabled']),
                      [(m['id'],
                        m['name'],
                        m['action'],
                        m['protocol'],
                        m['ip_version'],
                        m['enabled']) for m in fw_rules])

    @test.idempotent_id('0e8e13fb-13f3-42fc-9e97-c016bc69645a')
    def test_create_update_delete_firewall_rule(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id = body['firewall_rule']['id']

        # Update firewall rule
        body = self.firewall_rules_client.update_firewall_rule(fw_rule_id,
                                                               shared=True)
        self.assertTrue(body["firewall_rule"]['shared'])

        # Delete firewall rule
        self.firewall_rules_client.delete_firewall_rule(fw_rule_id)
        # Confirm deletion
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        self.assertNotIn(fw_rule_id,
                         [m['id'] for m in fw_rules['firewall_rules']])

    @test.idempotent_id('fb90dfb5-bb97-4191-a33c-4de7d5553629')
    def test_show_firewall_rule(self):
        # show a created firewall rule
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            self.fw_rule['id'])
        for key, value in six.iteritems(fw_rule['firewall_rule']):
            self.assertEqual(self.fw_rule[key], value)

    @test.idempotent_id('5fcf7de9-e2b2-4de8-8b8f-d6affd5adc92')
    def test_list_firewall_policies(self):
        fw_policies = self.firewall_policies_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertIn((self.fw_policy['id'],
                       self.fw_policy['name'],
                       self.fw_policy['firewall_rules']),
                      [(m['id'],
                        m['name'],
                        m['firewall_rules']) for m in fw_policies])

    @test.idempotent_id('206059c6-a574-40c2-820c-81474c599274')
    def test_create_update_delete_firewall_policy(self):
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        # Update firewall policy
        body = self.firewall_policies_client.update_firewall_policy(
            fw_policy_id,
            shared=True,
            name="updated_policy")
        updated_fw_policy = body["firewall_policy"]
        self.assertTrue(updated_fw_policy['shared'])
        self.assertEqual("updated_policy", updated_fw_policy['name'])

        # Delete firewall policy
        self.firewall_policies_client.delete_firewall_policy(fw_policy_id)
        # Confirm deletion
        fw_policies = self.firewall_policies_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertNotIn(fw_policy_id, [m['id'] for m in fw_policies])

    @test.idempotent_id('03189579-c485-412c-b033-4b12ab715b6e')
    def test_show_firewall_policy(self):
        # show a created firewall policy
        fw_policy = self.firewall_policies_client.show_firewall_policy(
            self.fw_policy['id'])
        fw_policy = fw_policy['firewall_policy']
        for key, value in six.iteritems(fw_policy):
            self.assertEqual(self.fw_policy[key], value)

    @test.idempotent_id('b496a8ff-7abc-4a3f-96d9-1acbbcde2ba9')
    def test_create_show_delete_firewall(self):
        # Create tenant network resources required for an ACTIVE firewall
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        self.addCleanup(self._try_delete_router, router)
        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])

        # Create firewall
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # show a created firewall
        firewall = self.firewalls_client.show_firewall(firewall_id)
        firewall = firewall['firewall']

        for key, value in six.iteritems(firewall):
            if key == 'status':
                continue
            self.assertEqual(created_firewall[key], value)

        # list firewall
        firewalls = self.firewalls_client.list_firewalls()
        firewalls = firewalls['firewalls']
        self.assertIn((created_firewall['id'],
                       created_firewall['name'],
                       created_firewall['firewall_policy_id']),
                      [(m['id'],
                        m['name'],
                        m['firewall_policy_id']) for m in firewalls])

        # Delete firewall
        self.firewalls_client.delete_firewall(firewall_id)

    # fortigate plugin only allow one router per tenant
    @test.idempotent_id('4ea48c81-27c2-49fd-8c8f-bb617dc0755c')
    def test_firewall_insertion_mode_add_remove_router(self):
        # Create router
        router1 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        self.addCleanup(self._try_delete_router, router1)
        # Create firewall on a router1
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router1['id']])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        self.assertEqual([router1['id']], created_firewall['router_ids'])

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # Remove router1 from the firewall
        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[])
        updated_firewall = body['firewall']
        self.assertNotIn(router1['id'], updated_firewall['router_ids'])
        self.assertEqual(0, len(updated_firewall['router_ids']))

    @test.idempotent_id('1b5cf8f6-cd2e-4f3f-aaa0-e12c079b6d22')
    def test_firewall_insertion_mode_one_firewall_per_router(self):
        # Create router required for an ACTIVE firewall
        router = self.create_router(
            data_utils.rand_name('router1-'),
            admin_state_up=True)
        self.addCleanup(self._try_delete_router, router)
        # Create firewall
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router['id']])
        created_firewall = body['firewall']
        self.addCleanup(self._try_delete_firewall, created_firewall['id'])

        # Try to create firewall with the same router
        self.assertRaisesRegexp(
            lib_exc.Conflict,
            "An object with that identifier already exists",
            self.firewalls_client.create_firewall,
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router['id']])

    @test.attr(type='smoke')
    @test.idempotent_id('4ebfac1d-d521-44de-a4a0-81b79312f362')
    def test_firewall_rule_insertion_position_removal_rule_from_policy(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id1 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id1)
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        # Insert rule to firewall policy
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')

        # Verify insertion of rule in policy
        self.assertIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id))
        # Create another firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="icmp")
        fw_rule_id2 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id2)

        # Insert rule to firewall policy after the first rule
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id2, fw_rule_id1, '')

        # Verify the position of rule after insertion
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id2)

        self.assertEqual(int(fw_rule['firewall_rule']['position']), 2)
        # Remove rule from the firewall policy
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id2)
        # Insert rule to firewall policy before the first rule
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id2, '', fw_rule_id1)
        # Verify the position of rule after insertion
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id2)
        self.assertEqual(int(fw_rule['firewall_rule']['position']), 1)
        # Remove rule from the firewall policy
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id2)
        # Verify removal of rule from firewall policy
        self.assertNotIn(fw_rule_id2, self._get_list_fw_rule_ids(fw_policy_id))

        # Remove rule from the firewall policy
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id1)

        # Verify removal of rule from firewall policy
        self.assertNotIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id))

    def _get_list_fw_rule_ids(self, fw_policy_id):
        fw_policy = self.firewall_policies_client.show_firewall_policy(
            fw_policy_id)
        return [ruleid for ruleid in fw_policy['firewall_policy']
                ['firewall_rules']]

    @test.idempotent_id('d08ce90f-b7f8-4a24-8b34-50d1b035e6c8')
    def test_update_firewall_policy_audited_attribute(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="icmp")
        fw_rule_id = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id)
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name('fw-policy'))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)
        self.assertFalse(body['firewall_policy']['audited'])
        # Update firewall policy audited attribute to true
        self.firewall_policies_client.update_firewall_policy(fw_policy_id,
                                           audited=True)
        # Insert Firewall rule to firewall policy
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id, '', '')
        body = self.firewall_policies_client.show_firewall_policy(
            fw_policy_id)
        self.assertFalse(body['firewall_policy']['audited'])
