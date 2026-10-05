JSON Web Signature (JWS)
========================

The jws Module implements the `JSON Web Signature`_ standard.
A JSON Web Signature is represented by a JWS object, related utility
classes and functions are available in this module too.

.. _JSON Web Signature: http://tools.ietf.org/html/rfc7515

Classes
-------

.. autoclass:: jwcrypto.jws.JWS
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.JWSCore
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.JWSCoreStreaming
   :members:
   :show-inheritance:

Variables
---------

.. autodata:: jwcrypto.jws.default_allowed_algs

Exceptions
----------

.. autoclass:: jwcrypto.jws.InvalidJWSSignature
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.InvalidJWSObject
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.jws.InvalidJWSOperation
   :members:
   :show-inheritance:

Registries
----------

.. autodata:: jwcrypto.jws.JWSHeaderRegistry
   :annotation:

Examples
--------

Sign a JWS token::
    >>> from jwcrypto import jwk, jws
    >>> from jwcrypto.common import json_encode
    >>> key = jwk.JWK.generate(kty='oct', size=256)
    >>> payload = "My Integrity protected message"
    >>> jwstoken = jws.JWS(payload.encode('utf-8'))
    >>> jwstoken.add_signature(key, None,
    ...                        json_encode({"alg": "HS256"}),
    ...                        json_encode({"kid": key.thumbprint()}))
    >>> sig = jwstoken.serialize()

Verify a JWS token::
    >>> jwstoken = jws.JWS()
    >>> jwstoken.deserialize(sig)
    >>> jwstoken.verify(key)
    >>> payload = jwstoken.payload

Sign a large payload as a detached, unencoded payload (RFC 7797) by
streaming it in chunks, without ever holding it whole in memory:

.. code-block:: python

    from jwcrypto import jwk, jws

    key = jwk.JWK.generate(kty='oct', size=256)
    protected = {"alg": "HS256", "b64": False, "crit": ["b64"]}
    jwstoken = jws.JWS()
    with open('large.bin', 'rb') as f:
        jwstoken.add_signature_stream(
            key, iter(lambda: f.read(65536), b''), protected=protected)
    sig = jwstoken.serialize()

Verify a JWS token with a detached payload streamed in chunks:

.. code-block:: python

    jwstoken = jws.JWS()
    jwstoken.deserialize(sig)
    with open('large.bin', 'rb') as f:
        jwstoken.verify_stream(key, iter(lambda: f.read(65536), b''))
