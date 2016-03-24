# Copyright 2016 Fortinet, Inc.
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

import math
import random
import string
import time

from networking_fortinet.api_client import exception


# generate a id with the specific prefix and the width
def uniqid(prefix='', more_entropy=False, width=11):
    width = width - len(prefix)
    if width <= 0:
        raise ValueError("The width '%(w)s' is too short to generate a id "
                         "with the prefix '%(p)s'" %
                         {'w': width, 'p': prefix})
    if not more_entropy:
        m = time.time()
        uniqid = '{num1:x}{num2:x}'.format(
            num1=int(math.floor(m)), num2=int((m - math.floor(m)) * 1000000))
    else:
        valid_chars = list(set(string.hexdigits.lower()))
        uniqid = ''
        for i in range(0, width, 1):
            uniqid += random.choice(valid_chars)
    if len(uniqid) >= width:
        uniqid = prefix + uniqid[len(uniqid) - width:]
    else:
        uniqid = prefix + uniqid.zfill(width)
    return uniqid


class Prepare_vdom(object):
    def __init__(self, apiclient, vdom=None):
        self.apiclient = apiclient
        self.vdom = vdom or uniqid(prefix='tst_', more_entropy=True)

    def __enter__(self):
        try:
            self.apiclient.request("GET_VDOM", name=self.vdom)
        except exception.ResourceNotFound:
            self.apiclient.request("ADD_VDOM", name=self.vdom)
        except Exception:
            raise EnvironmentError("Create vdom %(id)s failed" %
                                   {'id': self.vdom})
        return self

    def __exit__(self, type, value, traceback):
        try:
            if self.vdom not in ['root']:
                self.apiclient.request("DELETE_VDOM", name=self.vdom)
        except Exception:
            raise EnvironmentError("Delete vdom %(id)s failed" %
                                   {'id': self.vdom})
        return self
