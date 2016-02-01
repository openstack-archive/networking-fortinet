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


from networking_fortinet._i18n import _


class ApiException(Exception):
    """Base FortiOS API Client Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.

    """
    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            self._error_string = self.message % kwargs
        except Exception:
            # at least get the core message out if something happened
            self._error_string = self.message

    def __str__(self):
        return self._error_string


class UnAuthorizedRequest(ApiException):
    message = _("Server denied session's authentication credentials.")


class ResourceNotFound(ApiException):
    message = _("An entity referenced in the request was not found.")


class Conflict(ApiException):
    message = _("Request conflicts with configuration on a different "
                "entity.")


class Failed_dependency(ApiException):
    message = _("Request failed dependency.")


class ServiceUnavailable(ApiException):
    message = _("Request could not completed because the associated "
                "resource could not be reached.")


class Forbidden(ApiException):
    message = _("The request is forbidden from accessing the "
                "referenced resource.")


class ReadOnlyMode(Forbidden):
    message = _("Create/Update actions are forbidden when in read-only mode.")


class RequestTimeout(ApiException):
    message = _("The request has timed out.")


class BadRequest(ApiException):
    message = _("The server is unable to fulfill the request due "
                "to a bad syntax")


class InvalidSecurityCertificate(BadRequest):
    message = _("The backend received an invalid security certificate.")


def fourZeroZero(response=None):
    if response and "Invalid Certificate" in response.body:
        raise InvalidSecurityCertificate()
    raise BadRequest()


def fourZeroFour(response=None):
    raise ResourceNotFound()


def fourZeroNine(response=None):
    raise Conflict()


def fourTwoFour(response=None):
    raise Failed_dependency()


def fiveZeroThree(response=None):
    raise ServiceUnavailable()


def fourZeroThree(response=None):
    if 'read-only' in response.body:
        raise ReadOnlyMode()
    else:
        raise Forbidden()


def zero(self, response=None):
    raise ApiException()


ERROR_MAPPINGS = {
    301: zero,
    307: zero,
    400: fourZeroZero,
    403: fourZeroThree,
    404: fourZeroFour,
    405: zero,
    409: fourZeroNine,
    424: fourTwoFour,
    500: zero,
    501: zero,
    503: fiveZeroThree,
}
