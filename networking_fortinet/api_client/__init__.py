# Copyright 2015 Fortinet, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

try:
    import httplib
except ImportError:
    import http.client as httplib


def ctrl_conn_to_str(conn):
    """Returns a string representing a connection URL to the controller."""
    if isinstance(conn, httplib.HTTPSConnection):
        proto = "https://"
    elif isinstance(conn, httplib.HTTPConnection):
        proto = "http://"
    else:
        raise TypeError(_('Invalid connection type: %s') % type(conn))
    return "%s%s:%s" % (proto, conn.host, conn.port)
