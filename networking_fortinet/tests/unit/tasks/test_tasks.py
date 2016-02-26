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

import time
import uuid

import unittest2

from networking_fortinet.tasks import tasks


class TestTasks(unittest2.TestCase):

    def setUp(self, tasks_id=None):
        super(TestTasks, self).setUp()
        self.tasks_id = tasks_id if tasks_id else str(uuid.uuid1())
        self.tasks = tasks.Tasks(self.tasks_id)

    def tearDown(self, id=None):
        pass

    def test_register(self, **subtask):
        """
        subtask is a dictory, include two parts, func and params, it will
        be executed like subtask['func'](*subtask[params]), the following
        is a example format of subtask:
        'subtask':
                {'params': (
                    <api_client.client.FortiosApiClient object at 0x2a14a90>,
                    {'id': 2, 'vdom': 'root'}
                ),
                'func': <function wrapper at 0x2b62ed8>
                }
        """
        if not subtask:
            subtask = {
                'params': 1,
                'func': time.sleep
            }
        self.tasks.register(**subtask)
        self.assertIn(subtask, self.tasks._tasks)

    def test_register_existing_task(self, **subtask):
        """
        subtask is a dictory, include two parts, func and params, it will
        be executed like subtask['func'](*subtask[params]), the following
        is a example format of subtask:
        'subtask':
                {'params': (
                    <api_client.client.FortiosApiClient object at 0x2a14a90>,
                    {'id': 2, 'vdom': 'root'}
                ),
                'func': <function wrapper at 0x2b62ed8>
                }
        """
        if not subtask:
            subtask = {
                'params': 1,
                'func': time.sleep
            }
        self.tasks.register(**subtask)
        self.tasks.register(**subtask)
        count = self.tasks._tasks.count(subtask)
        self.assertEqual(1, count)

if __name__ == '__main__':
    unittest2.main()
