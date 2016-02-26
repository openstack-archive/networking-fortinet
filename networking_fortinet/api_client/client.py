# Copyright 2015 Fortinet, Inc.
#
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
#

import jinja2
from oslo_log import log as logging
from oslo_serialization import jsonutils

from networking_fortinet._i18n import _LE
from networking_fortinet.api_client import base
from networking_fortinet.api_client import eventlet_client
from networking_fortinet.api_client import eventlet_request
from networking_fortinet.api_client import exception
from networking_fortinet.api_client import templates
from networking_fortinet.common import singleton

LOG = logging.getLogger(__name__)


@singleton.singleton
class FortiosApiClient(eventlet_client.EventletApiClient):
    """The FortiOS API Client."""

    def __init__(self, api_providers, user, password,
                 concurrent_connections=base.DEFAULT_CONCURRENT_CONNECTIONS,
                 gen_timeout=base.GENERATION_ID_TIMEOUT,
                 use_https=False,
                 connect_timeout=base.DEFAULT_CONNECT_TIMEOUT,
                 http_timeout=75, retries=2, redirects=2):
        '''Constructor. Adds the following:
        :param api_providers: a list of tuples of the form: (host, port,
            is_ssl)
        :param http_timeout: how long to wait before aborting an
            unresponsive controller (and allow for retries to another
            controller in the cluster)
        :param retries: the number of concurrent connections.
        :param redirects: the number of concurrent connections.
        '''
        super(FortiosApiClient, self).__init__(
            api_providers, user, password,
            concurrent_connections=concurrent_connections,
            gen_timeout=gen_timeout, use_https=use_https,
            connect_timeout=connect_timeout)

        self._request_timeout = http_timeout * retries
        self._http_timeout = http_timeout
        self._retries = retries
        self._redirects = redirects
        self._version = None
        self.message = {}
        self._user = user
        self._password = password

    @staticmethod
    def _render(template, **message):
        '''Render API message from it's template

        :param template: defined API message with essential params.
        :param message: It is a dictionary, included values of the params
                        for the template
        '''
        if not message:
            message = {}
        msg = jinja2.Template(template).render(**message)
        return jsonutils.loads(msg)

    def request(self, opt, content_type="application/json", **message):
        '''Issues request to controller.'''
        self.message = self._render(getattr(templates, opt), **message)
        method = self.message['method']
        url = self.message['path']
        body = self.message['body'] if 'body' in self.message else None
        g = eventlet_request.GenericRequestEventlet(
            self, method, url, body, content_type, auto_login=True,
            http_timeout=self._http_timeout,
            retries=self._retries, redirects=self._redirects)
        g.start()
        response = g.join()

        # response is a modified HTTPResponse object or None.
        # response.read() will not work on response as the underlying library
        # request_eventlet.ApiRequestEventlet has already called this
        # method in order to extract the body and headers for processing.
        # ApiRequestEventlet derived classes call .read() and
        # .getheaders() on the HTTPResponse objects and store the results in
        # the response object's .body and .headers data members for future
        # access.

        if response is None:
            # Timeout.
            LOG.error(_LE('Request timed out: %(method)s to %(url)s'),
                      {'method': method, 'url': url})
            raise exception.RequestTimeout()

        status = response.status
        if status == 401:
            raise exception.UnAuthorizedRequest()
        # Fail-fast: Check for exception conditions and raise the
        # appropriate exceptions for known error codes.
        if status in exception.ERROR_MAPPINGS:
            LOG.error(_LE("Received error code: %s"), status)
            LOG.error(_LE("Server Error Message: %s"), response.body)
            exception.ERROR_MAPPINGS[status](response)

        # Continue processing for non-error condition.
        if (status != 200 and status != 201
                and status != 204):
            LOG.error(_LE("%(method)s to %(url)s, unexpected response code: "
                        "%(status)d (content = '%(body)s')"),
                      {'method': method, 'url': url,
                       'status': response.status, 'body': response.body})
            return None

        if url == jsonutils.loads(templates.LOGOUT)['path']:
            return response.body
        else:
            try:
                return jsonutils.loads(response.body)
            except UnicodeDecodeError:
                LOG.debug("The following strings cannot be decoded with "
                          "'utf-8, trying 'ISO-8859-1' instead. %(body)s",
                          {'body': response.body})
                return jsonutils.loads(response.body, encoding='ISO-8859-1')
            except Exception as e:
                LOG.error(_LE("Decode error, the response.body %(body)s"),
                          {'body': response.body})
                raise e
