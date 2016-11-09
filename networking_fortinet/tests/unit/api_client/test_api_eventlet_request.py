# Copyright (C) 2009-2012 VMware, Inc. All Rights Reserved.
# Copyright 2015 Fortinet, Inc. All Rights Reserved.
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

try:
    import httplib
except ImportError:
    import http.client as httplib
import random
import types

import eventlet
import mock
from oslo_log import log as logging
from oslotest import base
import six.moves.urllib as urllib

from networking_fortinet._i18n import _LI
from networking_fortinet.api_client import client as fortiosclient
from networking_fortinet.api_client import eventlet_client as client
from networking_fortinet.api_client import eventlet_request as request


LOG = logging.getLogger(__name__)


REQUEST_TIMEOUT = 1

EVT_CLIENT_PATH = client.EventletApiClient.__module__ + '.EventletApiClient'


def fetch(url):
    return urllib.urlopen(url).read()


class ApiRequestEventletTestCase(base.BaseTestCase):

    def setUp(self):

        super(ApiRequestEventletTestCase, self).setUp()
        self.client = client.EventletApiClient(
            [("127.0.0.1", 80, False)], "admin", "admin")
        self.url = "/abc"
        self.req = request.EventletApiRequest(self.client, self.url)
        self.fortiosclient = fortiosclient.FortiosApiClient(
            [("127.0.0.1", 80, False)], "admin", "admin")

    def tearDown(self):
        self.client = None
        self.req = None
        self.fortiosclient = None
        super(ApiRequestEventletTestCase, self).tearDown()

    def test_construct_eventlet_api_request(self):
        e = request.EventletApiRequest(self.client, self.url)
        self.assertIsNotNone(e)

    def test_apirequest_spawn(self):
        def x(id):
            eventlet.greenthread.sleep(random.random())

        for i in range(10):
            request.EventletApiRequest._spawn(x, i)

    def test_join_with_handle_request(self):
        self.req._handle_request = mock.Mock()
        self.req.start()
        self.req.join()
        self.assertTrue(self.req._handle_request.called)

    def test_join_without_handle_request(self):
        self.req._handle_request = mock.Mock()
        self.req.join()
        self.assertFalse(self.req._handle_request.called)

    def test_request_error(self):
        self.assertIsNone(self.req.request_error)

    def test_run_and_handle_request(self):
        self.req._request_timeout = None
        self.req._handle_request = mock.Mock()
        self.req.start()
        self.req.join()
        self.assertTrue(self.req._handle_request.called)

    def test_run_and_timeout(self):
        def my_handle_request(self):
            LOG.info(_LI('my_handle_request() self: %s'), self)
            LOG.info(_LI('my_handle_request() dir(self): %s'), dir(self))
            eventlet.greenthread.sleep(REQUEST_TIMEOUT * 2)

        self.req._request_timeout = REQUEST_TIMEOUT
        self.req._handle_request = types.MethodType(
            my_handle_request, self.req)
        self.req.start()
        self.assertIsNone(self.req.join())

    def prep_issue_request(
        self, url='coolurl', cookie='', mock_connection=True):
        mysock = mock.Mock()
        mysock.gettimeout.return_value = 4242

        myresponse = mock.Mock()
        myresponse.read.return_value = 'body'
        myresponse.getheaders.return_value = dict([('head', '1')])
        myresponse.status = 301

        myconn = mock.Mock()
        myconn.request.return_value = None
        myconn.sock = mysock
        myconn.getresponse.return_value = myresponse
        myconn.__str__ = mock.Mock()
        myconn.__str__.return_value = 'myconn string'

        req = self.req
        req._redirect_params = mock.Mock()
        req._redirect_params.return_value = (myconn, url)
        req._request_str = mock.Mock()
        req._request_str.return_value = 'http://cool/cool'

        client = self.client
        client.need_login = False
        client._auto_login = False
        client._auth_cookie = False
        if mock_connection:
            client.acquire_connection = mock.Mock()
            client.acquire_connection.return_value = myconn
        client.release_connection = mock.Mock()
        client.set_auth_cookie = mock.Mock()
        client._wait_for_login = mock.Mock()
        client.auth_cookie = mock.Mock()
        client.auth_cookie.return_value = cookie
        return (mysock, myresponse, myconn)

    def test_issue_request_trigger_exception(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        self.client.acquire_connection.return_value = None

        self.req._issue_request()
        self.assertIsInstance(self.req._request_error, Exception)
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_handle_none_sock(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        myconn.sock = None
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_exceed_maximum_retries(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        myresponse.status = 401
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_relogin(self):
        (mysock, myresponse, myconn) = self.prep_issue_request(
            url='login?redir=%2fapi%2fv2')
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client._wait_for_login.called)
        for args, kwargs in self.client.set_auth_cookie.call_args_list:
            if not args[1]:
                continue
            self.assertIsNotNone(args[1])

    def test_issue_request_with_cookie(self):
        (mysock, myresponse, myconn) = self.prep_issue_request(
            cookie=dict([('Cookie', 'ck'), ('X-CSRFTOKEN', 'tk')]))
        self.req.start()
        self.req.join()
        self.assertTrue(myconn.request.called)
        for args, kwargs in myconn.request.call_args_list:
            if "Cookie" not in args[3]:
                continue
            self.assertEqual(args[3]["Cookie"], 'ck')

    #TODO(jerryz): something didn't run
    def noop_test_issue_request_ok(self):
        (mysock, myresponse, myconn) = self.prep_issue_request(
            cookie=dict([('Cookie', 'ck'), ('X-CSRFTOKEN', 'tk')]))
        myresponse.status = 200
        self.req.start()
        self.assertIsNotNone(self.req.join())

    def test_acquire_connection_ok(self):
        (mysock, myresponse, myconn) = self.prep_issue_request(
            mock_connection=False)
        conn = self.client.acquire_connection(
            self, headers=None, rid=-1)
        self.assertIsInstance(
            conn, httplib.HTTPConnection)

    def test_issue_request_with_no_cookie(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        myresponse.status = 401
        self.req.start()
        self.assertIsNone(self.req.join())
        self.client.set_auth_cookie.assert_called_with(myconn, None)

    def test_issue_request_exceed_maximum_redirects(self):
        logger = logging.getLogger(
            'networking_fortinet.api_client.request')
        with mock.patch.object(logger, 'info') as mock_log:
            (mysock, myresponse, myconn) = self.prep_issue_request()
            self.req.start()
            self.assertIsNone(self.req.join())
            self.assertTrue(self.client.acquire_connection.called)
            for args, kwargs in mock_log.call_args_list:
                if "Maximum redirects exceeded" not in args:
                    continue
                self.assertTrue("Maximum redirects exceeded" in args)
            self.assertTrue(mock_log.called)

    def test_issue_request_refresh_cookie(self):
        (mysock, myresponse, myconn) = self.prep_issue_request(
            cookie=dict([('Cookie', 'old'), ('X-CSRFTOKEN', 'tk')]))
        myresponse.status = 401
        self.req.start()
        self.assertIsNone(self.req.join())
        self.client.set_auth_cookie.assert_called_with(myconn, None)

    def test_issue_request_unavailable(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        myresponse.status = 503
        self.req.start()
        self.assertIsNone(self.req.join())
        self.client.release_connection.called_with(
            myconn, True, True, mock.ANY)

#    def test_issue_request_internal_server_error(self):
#        (mysock, myresponse, myconn) = self.prep_issue_request()
#        myresponse.status = httplib2.INTERNAL_SERVER_ERROR
#        with self.assertRaises(Exception, 'Server error return: 500'):
#        self.req.start()
#        self.assertIsNone(self.req.join())

    def test_issue_request_trigger_non_redirect(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        myresponse.status = 200
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_issue_request_trigger_internal_server_error(self):
        (mysock, myresponse, myconn) = self.prep_issue_request()
        self.req._redirect_params.return_value = (myconn, None)
        self.req.start()
        self.assertIsNone(self.req.join())
        self.assertTrue(self.client.acquire_connection.called)

    def test_redirect_params_break_on_location(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', None)])
        self.assertIsNone(retval)

    def test_redirect_params_parse_a_url(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', '/path/a/b/c')])
        self.assertIsNotNone(retval)

    def test_redirect_params_invalid_redirect_location(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', '+path/a/b/c')])
        self.assertIsNone(retval)

    def test_redirect_params_invalid_scheme(self):
        myconn = mock.Mock()
        (conn, retval) = self.req._redirect_params(
            myconn, [('location', 'invalidscheme://hostname:1/path')])
        self.assertIsNone(retval)

    def test_redirect_params_setup_https_with_cookie(self):
            self.req._api_client = self.fortiosclient
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(
                myconn, [('location', 'https://host:1/path')])

            self.assertIsNotNone(retval)
            self.assertIsInstance(conn, httplib.HTTPSConnection)

    def test_redirect_params_setup_http_with_cookie(self):
            self.req._api_client = self.fortiosclient
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(
                myconn, [('location', 'http://host:1/path')])

            self.assertIsNotNone(retval)
            self.assertIsInstance(conn, httplib.HTTPConnection)

    def test_redirect_params_setup_http_existing_pool(self):
            self.req._api_client = self.fortiosclient
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(
                myconn, [('location', 'http://127.0.0.1:80/abc')])

            self.assertIsNotNone(retval)
            self.assertIsInstance(conn, httplib.HTTPConnection)

    def test_redirect_params_setup_https_and_query(self):
        with mock.patch(EVT_CLIENT_PATH) as mock_client:
            api_client = mock_client.return_value
            self.req._api_client = api_client
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(myconn, [
                ('location', 'https://host:1/path?q=1')])

            self.assertIsNotNone(retval)
            self.assertTrue(api_client.acquire_redirect_connection.called)

    def test_redirect_params_setup_https_connection_no_cookie(self):
        with mock.patch(EVT_CLIENT_PATH) as mock_client:
            api_client = mock_client.return_value
            self.req._api_client = api_client
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(myconn, [
                ('location', 'https://host:1/path')])

            self.assertIsNotNone(retval)
            self.assertTrue(api_client.acquire_redirect_connection.called)

    def test_redirect_params_setup_https_and_query_no_cookie(self):
        with mock.patch(EVT_CLIENT_PATH) as mock_client:
            api_client = mock_client.return_value
            self.req._api_client = api_client
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(
                myconn, [('location', 'https://host:1/path?q=1')])
            self.assertIsNotNone(retval)
            self.assertTrue(api_client.acquire_redirect_connection.called)

    def test_redirect_params_path_only_with_query(self):
        with mock.patch(EVT_CLIENT_PATH) as mock_client:
            api_client = mock_client.return_value
            api_client.wait_for_login.return_value = None
            api_client.auth_cookie = None
            api_client.acquire_connection.return_value = True
            myconn = mock.Mock()
            (conn, retval) = self.req._redirect_params(myconn, [
                ('location', '/path?q=1')])
            self.assertIsNotNone(retval)

    def test_handle_request_auto_login(self):
        self.req._auto_login = True
        self.req._api_client = mock.Mock()
        self.req._api_client.need_login = True
        self.req._request_str = mock.Mock()
        self.req._request_str.return_value = 'http://cool/cool'
        self.req.spawn = mock.Mock()
        self.req._handle_request()

    def test_handle_request_auto_login_unauth(self):
        self.req._auto_login = True
        self.req._api_client = mock.Mock()
        self.req._api_client.need_login = True
        self.req._request_str = mock.Mock()
        self.req._request_str.return_value = 'http://cool/cool'

        import socket
        resp = httplib.HTTPResponse(socket.socket())
        resp.status = 401
        mywaiter = mock.Mock()
        mywaiter.wait = mock.Mock()
        mywaiter.wait.return_value = resp
        self.req.spawn = mock.Mock(return_value=mywaiter)
        self.req._handle_request()

    def test_construct_eventlet_get_api_providers_request(self):
        r = request.GetApiProvidersRequestEventlet(self.client)
        self.assertIsNotNone(r)

    def test_api_providers_none_api_providers(self):
        r = request.GetApiProvidersRequestEventlet(self.client)
        r.successful = mock.Mock(return_value=False)
        self.assertIsNone(r.api_providers())

    def test_api_providers_non_none_api_providers(self):
        r = request.GetApiProvidersRequestEventlet(self.client)
        r.value = mock.Mock()
        r.value.body = """{
          "results": [
            { "roles": [
              { "role": "api_provider",
                "listen_addr": "pssl:1.1.1.1:1" }]}]}"""
        r.successful = mock.Mock(return_value=True)
        self.assertIsNotNone(r.api_providers())

    def test_construct_eventlet_login_request(self):
        r = request.LoginRequestEventlet(self.fortiosclient, 'user',
            'password')
        self.assertIsNotNone(r)

    def test_session_cookie_session_cookie_retrieval(self):
        r = request.LoginRequestEventlet(self.fortiosclient, 'user',
            'password')
        r.successful = mock.Mock()
        r.successful.return_value = True
        r.value = mock.Mock()
        r.value.get_header = mock.Mock()
        r.value.get_header.return_value = 'cool'
        self.assertIsNotNone(r.session_cookie())

    def test_session_cookie_not_retrieved(self):
        r = request.LoginRequestEventlet(self.fortiosclient, 'user',
            'password')
        r.successful = mock.Mock()
        r.successful.return_value = False
        r.value = mock.Mock()
        r.value.get_header = mock.Mock()
        r.value.get_header.return_value = 'cool'
        self.assertIsNone(r.session_cookie())
