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

import mock
import unittest2

from networking_fortinet.api_client import client
from networking_fortinet.api_client import eventlet_request as request
from networking_fortinet.api_client import exception

E_R_CLS = request.GenericRequestEventlet.__name__


class ClientTestCase(unittest2.TestCase):
    def setUp(self):
        super(ClientTestCase, self).setUp()
        self.api = [("foobar", 443, True)]
        self.user = "admin"
        self.password = ""
        self.client = client.FortiosApiClient(
            self.api, self.user, self.password)
        self.message = {
                    "name": "ext_4093",
                    "vlanid": 4093,
                    "vdom": "root",
                    "interface": "port1",
                    "ip": "192.168.30.254 255.255.255.0"
                   }

    def tearDown(self):
        self.client = None
        super(ClientTestCase, self).tearDown()

    def test_send_request_unknown_opt(self):
        with self.assertRaises(AttributeError):
            self.client.request('UNKNOWN_OPT')

    def test_send_request_good_return(self):
        with mock.patch(__name__ + '.request.' + E_R_CLS) as MockClass:
            instance = MockClass.return_value
            resp = mock.Mock()
            resp.status = int(200)
            resp.body = '{"perfect": "body"}'
            instance.start.return_value = 'good1'
            instance.join.return_value = resp
            body = self.client.request('ADD_VLAN_INTERFACE', **self.message)
            self.assertEqual(body['perfect'], 'body')

    def test_send_request_unauthorized(self):
        with mock.patch(__name__ + '.request.' + E_R_CLS) as MockClass:
            instance = MockClass.return_value
            resp = mock.Mock()
            resp.status = int(401)
            resp.body = '{}'
            instance.start.return_value = 'good1'
            instance.join.return_value = resp
            with self.assertRaises(exception.UnAuthorizedRequest):
                self.client.request('ADD_VLAN_INTERFACE', **self.message)

    def test_send_request_error_mapping(self):
        with mock.patch(__name__ + '.request.' + E_R_CLS) as MockClass:
            instance = MockClass.return_value
            instance.start.return_value = 'good1'
            instance.join.return_value.status = int(400)
            instance.join.return_value.body = '{"Invalid Certificate": ""}'
            with self.assertRaises(exception.InvalidSecurityCertificate):
                self.client.request('ADD_VLAN_INTERFACE', **self.message)
            instance.join.return_value.body = '{"Bad Request": ""}'
            with self.assertRaises(exception.BadRequest):
                self.client.request('ADD_VLAN_INTERFACE', **self.message)
