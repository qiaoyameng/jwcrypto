External Key Operations (HSM / Remote Signing)
==============================================

When a private key resides in a Hardware Security Module, a Trusted
Execution Environment or a remote signing service, the application can
only retrieve the public key as a JWK; the private part cannot be
exported.

The :mod:`jwcrypto.extkey` module provides an explicit adapter,
:class:`jwcrypto.extkey.ExternalKey`, that records the public key
metadata together with the algorithms and private operations the caller
allows.  Private operations are performed by caller-provided callbacks
that forward the request to the external provider.

The adapter is *not* a :class:`jwcrypto.jwk.JWK` and it never carries
private key values such as the RSA ``d`` parameter.

Supported operations
--------------------

* ``sign``: create a JWS signature.  The callback receives the exact
  JWS Signing Input defined by RFC 7515 and must return the raw
  signature bytes (JOSE R || S encoding for ECDSA).  Supported
  algorithms are the asymmetric JWS algorithms (RS*, PS*, ES*, EdDSA,
  Ed25519, Ed448 and, when available, the ML-DSA algorithms); HMAC
  algorithms are not supported.
* ``unwrapKey``: decrypt a JWE Content Encryption Key with an RSA key
  transport algorithm (``RSA1_5``, ``RSA-OAEP`` or
  ``RSA-OAEP-256``).  The callback receives the raw JWE Encrypted Key
  and the required CEK size, and must return the unwrapped CEK bytes.

Before a callback is invoked the adapter verifies that:

* the algorithm is in the caller's allow list;
* the ``alg`` value of the JOSE header is in that allow list;
* the operation is enabled and is permitted by the public JWK ``use``
  and ``key_ops`` metadata (an encryption-only key cannot sign);
* the public key type, curve and (for AKP keys) ``alg`` match the
  algorithm.

Values returned by a callback are checked for the type, length and
format the algorithm requires; malformed responses raise
:class:`jwcrypto.extkey.ExternalKeyInvalidResponse`.

Tokens produced through an external key can be verified or decrypted by
other parties using the ordinary public JWK code paths.

Classes
-------

.. autoclass:: jwcrypto.extkey.ExternalKey
   :members:
   :show-inheritance:

Exceptions
----------

.. autoclass:: jwcrypto.extkey.ExternalKeyError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.extkey.ExternalKeyOperationRejected
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.extkey.ExternalKeyInvalidResponse
   :members:
   :show-inheritance:
