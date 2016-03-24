# Copyright 2015 Fortinet, Inc.
# All Rights Reserved
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

import inspect
import unittest2

from networking_fortinet.api_client import client
from networking_fortinet.tests.common import utils

PREFIX = 'test_CRUD_'


class ClientTestCase(unittest2.TestCase):
    def setUp(self, fgtip=None, port=443, protocol='https', username='admin',
              password=''):
        super(ClientTestCase, self).setUp()
        fgtip = '10.160.37.96' if not fgtip else fgtip
        api_server = [(fgtip, port, 'https' == protocol)]
        self.client = client.FortiosApiClient(api_server, username, password)
        self.vdom = 'root'

    def tearDown(self):
        self.client.request('LOGOUT')
        super(ClientTestCase, self).tearDown()

    def _func_name(self):
        return inspect.stack()[1][3]

    def _test(self, name, create_msg, query_msg, update_msg, key=None):
        if name.startswith(PREFIX):
            name = name[len(PREFIX):]
        name = name.upper()
        with utils.Prepare_vdom(self.client, vdom=self.vdom) as env:
            try:
                create_msg.setdefault('vdom', env.vdom)
                res = self.client.request('ADD_%s' % name, **create_msg)
                self.assertEqual(200, res.get('http_status', None))
                if key:
                    query_msg.setdefault('vdom', env.vdom)
                    query_msg.setdefault(
                        key, res['results'].get('mkey', None))
                    update_msg.setdefault('vdom', env.vdom)
                    update_msg.setdefault(
                        key, res['results'].get('mkey', None))

                res = self.client.request('GET_%s' % name, **query_msg)
                self.assertEqual(200, res.get('http_status', None))
                if update_msg:
                    res = self.client.request('SET_%s' % name, **update_msg)
                    self.assertEqual(200, res.get('http_status', None))
                    res = self.client.request('GET_%s' % name, **query_msg)
                    self.assertEqual(200, res.get('http_status', None))

                res = self.client.request('DELETE_%s' % name, **query_msg)
                self.assertEqual(200, res.get('http_status', None))
            except Exception:
                self.client.request('DELETE_%s' % name, **query_msg)
                #print("No %(name)s need to be deleted" % {'name': name})

    def test_CRUD_firewall_policy(self):
        create_msg = {
            'dstintf': 'port3',
            'srcintf': 'port4',
            'action': 'deny',
            'webfilter_profile': 'default'
        }
        query_msg = {}
        update_msg = {
            'dstintf': 'port5',
            'srcintf': 'port6',
            'action': 'deny'
        }
        self._test(
            self._func_name(), create_msg, query_msg, update_msg, key='id')

    def test_CRUD_firewall_address(self):
        name = self._func_name()
        create_msg = {
            'name': name,
            "subnet": "192.168.44.0 255.255.255.0"
        }
        query_msg = {'name': name}
        update_msg = {
            'name': name,
            "subnet": "10.1.1.0 255.255.255.252"
        }
        self._test(name, create_msg, query_msg, update_msg)

    def test_CRUD_firewall_service(self):
        create_msg = {
            'name': self._func_name(),
            'tcp_portrange': '100-200:300-400',
            'comment': self._func_name()
        }
        query_msg = {'name': self._func_name()}
        update_msg = {
            'name': self._func_name(),
            'protocol': 'ICMP'
        }
        self._test(self._func_name(), create_msg, query_msg, update_msg)


if __name__ == '__main__':
    unittest2.main()
