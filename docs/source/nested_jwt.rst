Nested JSON Web Token (Nested JWT)
==================================

The nested_jwt Module implements the "nested JWT" structure from
Section 11.2 of `JSON Web Token`_, restricted to the only ordering this
API accepts: the claims are signed first (an inner JWS) and then
encrypted (an outer JWE).

The outer JWE and the inner JWS are configured independently: each
layer has its own key source, allowed algorithms and ``typ``/``cty``
policy. Verification is always performed in a fixed order:

1. The outer token is required to be a JWE in compact serialization and
   is decrypted with the outer key only after its algorithms and
   ``typ``/``cty`` headers match the configuration.
2. The decrypted content is required to be a JWS in compact
   serialization and is verified with the inner key. The inner key is
   selected solely from the inner JWS header; outer headers are never
   trusted for that purpose.
3. Only after the signature verifies are the claims exposed, and
   issuer, audience and time (``exp``/``nbf``) checks are performed.

No format guessing is performed: a JWE is always expected outside and a
JWS inside, the number of layers is fixed at two, and both the raw
token and the decompressed inner content are size limited.

.. _JSON Web Token: http://tools.ietf.org/html/rfc7519#section-11.2

Classes
-------

.. autoclass:: jwcrypto.nested_jwt.NestedJWT
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.nested_jwt.NestedJWTConfig
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.nested_jwt.NestedJWTLayer
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.nested_jwt.ANY
   :members:

Exceptions
----------

.. autoclass:: jwcrypto.nested_jwt.InvalidNestedJWT
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.nested_jwt.default_allowed_keymgmt_algs

.. autodata:: jwcrypto.nested_jwt.default_allowed_enc_algs

.. autodata:: jwcrypto.nested_jwt.default_allowed_sign_algs

.. autodata:: jwcrypto.nested_jwt.default_max_inner_size

.. autodata:: jwcrypto.nested_jwt.default_max_token_size

Examples
--------

Create and verify a nested JWT with a symmetric key::

    >>> from jwcrypto import jwk, nested_jwt
    >>> key = jwk.JWK(generate='oct', size=256)
    >>> token = nested_jwt.NestedJWT.sign_and_encrypt(
    ...     claims={'iss': 'me', 'sub': 'you'},
    ...     signing_key=key,
    ...     encryption_key=key)
    >>> config = nested_jwt.NestedJWTConfig(outer=key, inner=key)
    >>> nj = nested_jwt.NestedJWT(token, config=config,
    ...                          check_claims={'iss': 'me'})
    >>> nj.claims_dict['sub']
    'you'
