# Copyright 2015 Fortinet Inc.
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

"""
This module provides a decorator for adding the sigleton feature to classes.
Example usage:

   >>> @singleton
   ... class SpamaTon(object):
   ...     def __init__(self,  adjunct):
   ...         self.adjunct = adjunct
   ...
   ...     def spam_adjunct(self):
   ...         return self.adjunct
   ...
   >>> EggJunc = SpamaTon("Eggs")
   >>> HamJunc = SpamaTon("Ham")
   >>> print('Spam with ' + EggJunc.spam_adjunct())
   Spam with Ham

   >>> @singleton
   ... class SingleInitSpamaTon(object):
   ...     @ignore_subsequent
   ...     def __init__(self,  adjunct):
   ...         self.adjunct = adjunct
   ...
   ...     def spam_adjunct(self):
   ...         return self.adjunct
   ...
   >>> EggJunc = SingleInitSpamaTon("Eggs")
   >>> HamJunc = SingleInitSpamaTon("Ham")
   >>> print('Spam with ' + HamJunc.spam_adjunct())
   Spam with Eggs

For inheritance from a singleton (discouraged) __new__ needs to be overwritten
or the subclass will share its instance.
Example:
   >>> @singleton
   ... class SpamaTon(object):
   ...     def __init__(self,  adjunct):
   ...         self.adjunct = adjunct
   ...
   ...     def spam_adjunct(self):
   ...         return self.adjunct
   ...
   >>> @singleton
   ... class SubSpamaTon(SpamaTon):
   ...     def __new__(cls,  *args,  **kwargs):
   ...         return super(SpamaTon.__class__,  cls).__new__(cls)
   ...
   ...     def __init__(self,  adjunct,  second_adjunct):
   ...         super(SubSpamaTon,  self).__init__(adjunct)
   ...         self.second_adjunct = second_adjunct
   ...
   ...     def spam_adjunct(self):
   ...         return ' and '.join([self.adjunct,  self.second_adjunct])
   ...
   >>> MultiJunc = SubSpamaTon("Ham",  "Eggs")
   >>> print('Spam with ' + MultiJunc.spam_adjunct())
   Spam with Ham and Eggs
"""
import functools

try:
    import threading as _threading
except ImportError:
    import dummy_threading as _threading


class SingletonFactory(object):
    """Takes a class and produces a singleton."""

    def __init__(self, cls, lock):
        """Create a new SingletonFactory.
       Keyword arguments:
       cls -- class to produce singleton from
       lock -- Lock object shared between threads to synchronize instance
       access
       """
        self._lock = lock
        self._old_cls = cls
        self._instance = None

    def get_new(self):
        """Returns a replacement for the __new__ functions of the class to
       turn into a singleton. The replacement first will lock access for other
       threads. Then a new instance of the singleton is created. Further
       constructor calls will result in a reference to the single instance.
       The replacement function is wrapped to be transparent to any changes to
       __new__ in the original class.
       """

        @functools.wraps(self._old_cls.__new__)
        def new_instantiated(cls, *args, **kwargs):
            """Called to get an existing instance of a singleton.
           Keyword arguments:
           cls, args, kwargs -- ignored, exist for calling conventions only
           """
            return self._instance

        @functools.wraps(self._old_cls.__new__)
        def new_uninstantiated(cls, *args, **kwargs):
            """Called when a new singleton instance is created.
           This first locks access for other threads. Then a new instance of
           cls is created and further calls to __new__ are replaced by
           new_instantiated
           Keyword arguments:
           cls -- instantiated class
           args, kwargs -- optional arguments to pass to __init__ of the
           instatiated class
           """

            with self._lock:
                if not self._instance:
                    self._instance = self._old_cls.__new__(cls)
                    cls.__new__ = classmethod(new_instantiated)

            return self._instance

        return classmethod(new_uninstantiated)

    def __call__(self):
        """Produces a singleton.
       Returns a copy of the original class which has its __new__ method
       replaced by new_uninstantiated
       """
        new_cls = type(self._old_cls.__name__, self._old_cls.__bases__,
                       dict(self._old_cls.__dict__))
        new_cls.__new__ = self.get_new()
        return new_cls


def singleton(cls):
    """Decorates a class making it a singleton.
   Keyword arguments:
   cls -- class to decorate.
   """
    factory = SingletonFactory(cls, _threading.RLock())
    return factory()


def ignore_subsequent(instance_method):
    """Decorates an instance method to be ignored if called subsequently.
   Keyword arguments:
   instance_method -- instance method to be decorated
   """

    @functools.wraps(instance_method)
    def ignore_method(self, *args, **kwargs):
        pass

    @functools.wraps(instance_method)
    def first_method(self, *args, **kwargs):
        instance_method(self, *args, **kwargs)
        setattr(self.__class__, instance_method.__name__, ignore_method)

    return first_method


if __name__ == "__main__":
    import doctest

    doctest.testmod()
