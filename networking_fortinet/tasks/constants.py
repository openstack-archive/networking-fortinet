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


class TaskStatus(object):
    """Task running status.

    This is used by execution/status callback function to notify the
    task manager what's the status of current task, and also used for
    indication the final task execution result.
    NONE - Reg -> PENDING --OK--> COMPLETED
                  |              /\
                  |              |
                  |              OK
                  |              |
                  -- NOK --> ROLLBACK  -- NOK --> ERROR
    """
    NONE = 0
    PENDING = 1
    ROLLBACK = 2
    COMPLETED = 3
    ERROR = 4
    ABORT = 5
