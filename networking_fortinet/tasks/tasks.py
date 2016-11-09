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

import collections
import uuid

from eventlet import event
from eventlet import greenthread
from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_service import loopingcall
import six

from networking_fortinet._i18n import _, _LE, _LI
from networking_fortinet.common import resources
from networking_fortinet.common import singleton
from networking_fortinet.tasks import constants


DEFAULT_INTERVAL = 1000

LOG = logging.getLogger(__name__)


def nop(task):
    return constants.TaskStatus.COMPLETED


class TaskException(exceptions.NeutronException):

    def __init__(self, message=None, **kwargs):
        if message is not None:
            self.message = message
        super(TaskException, self).__init__(**kwargs)


class InvalidState(TaskException):
    message = _("Invalid state %(state)d")


class TaskStateSkipped(TaskException):
    message = _("State %(state)d skipped. Current state %(current)d")


class Tasks(object):
    def __init__(self, id):
        #self.name = name if name else uuid.uuid1()
        #self.client = client
        # self._tasks is a stack to store the rollback tasks of tasks executed.
        # self._tasks example
        # [
        #   {
        #       'data': {'vdom': 'osvdm1'},
        #       'func': <function wrapper at 0x3ee2140>
        #   },
        #   {
        #       'data': {'vdom': 'osvdm1'},
        #       'func': <function wrapper at 0x3ee21b8>
        #   }
        # ]
        self._tasks = collections.deque()
        # task id should be unified, here we can use context.request_id
        self.id = id if id else str(uuid.uuid1())
        self.state = event.Event()
        self.status = constants.TaskStatus.NONE
        self.status_handlers = {
            constants.TaskStatus.ROLLBACK: self.execute,
            constants.TaskStatus.COMPLETED: self._finished,
            constants.TaskStatus.ERROR: self._finished,
            constants.TaskStatus.ABORT: self._finished
        }

    def register(self, **subtask):
        if subtask in self._tasks:
            return
        self._tasks.append(subtask)
        self._update_status(constants.TaskStatus.PENDING)
        return self

    def _reset_tasks(self, status=constants.TaskStatus.NONE):
        while len(self._tasks):
            self._tasks.pop()
        self.status = status

    def execute(self):
        if constants.TaskStatus.ROLLBACK != self.status:
            return
        while len(self._tasks):
            try:
                subtask = self._tasks.pop()
                subtask['func'](*subtask['params'])
            except Exception:
                msg = (_("Task %(task)s encountered exception in %(func)s "),
                       {'task': str(self), 'func': str(subtask['func'])})
                self.status = constants.TaskStatus.ERROR
                self._tasks = {}
                LOG.exception(msg)
        return self._update_status(constants.TaskStatus.COMPLETED)

    def _update_status(self, status):
        if status != self.status:
            self.status = status
            if status in self.status_handlers.keys():
                self.status_handlers[status]()
        return self.status

    def _finished(self):
        self._reset_tasks(constants.TaskStatus.COMPLETED)

    def wait(self):
        if constants.TaskStatus.NONE == self.status:
            return
        status = self.state.wait()
        self.status_handlers[status]()

    def __repr__(self):
        return "Task-%s" % (self.id)


@singleton.singleton
class TaskManager(object):

    _instance = None
    _default_interval = DEFAULT_INTERVAL

    def __init__(self, interval=None):
        self._interval = interval or TaskManager._default_interval

        # A queue to pass tasks from other threads
        self._tasks_queue = collections.deque()

        # A dict to task id
        self._tasks = {}

        # Current task being executed in main thread
        self._main_thread_exec_task = None

        # New request event
        self._req = event.Event()

        # TaskHandler stopped event
        self._stopped = False

        # Periodic function trigger
        self._monitor = None
        self._monitor_busy = False

        # Thread handling the task request
        self._thread = None

    def _execute(self, task):
        """Execute task."""
        msg = _("@@@ Start task %s") % str(task)
        LOG.debug(msg)
        try:
            task.wait()
        except Exception:
            msg = (_("Task %(task)s encountered exception"),
                {'task': str(task)})
            LOG.exception(msg)
            #status = constants.TaskStatus.ERROR
        LOG.debug("Task %(task)s return", {'task': str(task)})

    def _result(self, task):
        """Notify task execution result."""
        try:
            return
        except Exception:
            msg = _("Task %(task)s encountered exception in %(cb)s") % {
                'task': str(task),
                'cb': str(task._result_callback)}
            LOG.exception(msg)

        LOG.debug("Task %(task)s return %(status)s",
                  {'task': str(task), 'status': task.status})

        task._finished()

    def _check_pending_tasks(self):
        """Check all pending tasks status."""
        for id in self._tasks.keys():
            if self._stopped:
                # Task manager is stopped, return now
                return
            task = self._tasks[id]
            # only the first task is executed and pending
            if constants.TaskStatus.PENDING != task.status:
                self._dequeue(task)

    def _enqueue(self, id):
        if id not in self._tasks:
            self._tasks[id] = Tasks(id)
            self._tasks_queue.append(self._tasks[id])

    def _dequeue(self, task):
        if task in self._tasks_queue:
            self._tasks_queue.remove(task)
            del self._tasks[task.id]
            return

    def update_status(self, id, status):
        if id in self._tasks:
            self._tasks[id]._update_status(status)

    def _abort(self):
        """Abort all tasks."""
        # put all tasks haven't been received by main thread to queue
        # so the following abort handling can cover them
        for t in self._tasks_queue:
            self._enqueue(t)
        self._tasks_queue.clear()

        for id in self._tasks.keys():
            tasks = list(self._tasks[id])
            for task in tasks:
                task._update_status(constants.TaskStatus.ABORT)
                self._dequeue(task)

    def _get_task(self):
        """Get task request."""
        while True:
            for t in self._tasks_queue:
                if t.status in [constants.TaskStatus.ROLLBACK,
                                constants.TaskStatus.COMPLETED]:
                    return t
            self._req.wait()
            self._req.reset()

    def run(self):
        while True:
            try:
                if self._stopped:
                    # Gracefully terminate this thread if the _stopped
                    # attribute was set to true
                    LOG.info(_LI("Stopping TaskManager"))
                    break

                # get a task from queue, or timeout for periodic status check
                task = self._get_task()

                try:
                    #if constants.TaskStatus.ROLLBACK == task.status:
                    self._main_thread_exec_task = task
                    self._execute(task)
                finally:
                    self._main_thread_exec_task = None
                    if task.status in [constants.TaskStatus.NONE,
                                       constants.TaskStatus.ERROR,
                                       constants.TaskStatus.COMPLETED]:
                        # The thread is killed during _execute(). To guarantee
                        # the task been aborted correctly, put it to the queue.
                        #self._enqueue(task)
                        self._dequeue(task)
                    else:
                        self._enqueue(task)
            except Exception:
                LOG.exception(_LE("TaskManager terminating because "
                                "of an exception"))
                break

    def add(self, id, **subtask):
        if id is None:
            id = str(uuid.uuid1())
        if subtask:
            self._enqueue(id)
            self._tasks[id].register(**subtask)

    def stop(self):
        if self._thread is None:
            return
        self._stopped = True
        self._thread.kill()
        self._thread = None
        # Stop looping call and abort running tasks
        self._monitor.stop()
        if self._monitor_busy:
            self._monitor.wait()
        self._abort()
        LOG.info(_LI("TaskManager terminated"))

    def has_pending_task(self):
        if self._tasks_queue or self._tasks or self._main_thread_exec_task:
            return True
        else:
            return False

    def show_pending_tasks(self):
        for task in self._tasks_queue:
            LOG.info(str(task))
        for resource, tasks in six.iteritems(self._tasks):
            for task in tasks:
                LOG.info(str(task))
        if self._main_thread_exec_task:
            LOG.info(str(self._main_thread_exec_task))

    def count(self):
        count = 0
        for id, tasks in six.iteritems(self._tasks):
            count += len(tasks)
        return count

    def start(self, interval=None):
        def _inner():
            self.run()

        def _loopingcall_callback():
            self._monitor_busy = True
            try:
                self._check_pending_tasks()
            except Exception as e:
                resources.Exinfo(e)
                LOG.exception(_LE("Exception in _check_pending_tasks"))
            self._monitor_busy = False

        if self._thread is not None:
            return self

        if interval is None or interval == 0:
            interval = self._interval

        self._stopped = False
        self._thread = greenthread.spawn(_inner)
        self._monitor = loopingcall.FixedIntervalLoopingCall(
            _loopingcall_callback)
        self._monitor.start(interval / 1000.0,
                            interval / 1000.0)
        # To allow the created thread start running
        greenthread.sleep(0)
        return self

    @classmethod
    def set_default_interval(cls, interval):
        cls._default_interval = interval
