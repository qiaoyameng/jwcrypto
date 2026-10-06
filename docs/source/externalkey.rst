External Key Adapters
=====================

The externalkey Module provides an explicit integration point for private
keys that cannot be exported from the process, such as keys held by a
hardware security module (HSM), a smart card, or a remote key vault.

The application receives only the public key as a standard JWK. Private key
operations are delegated to caller provided callbacks; the private key
material never needs to be loaded by jwcrypto.

An :class:`jwcrypto.externalkey.ExternalKeyAdapter` is **not** a
:class:`jwcrypto.jwk.JWK`: it does not contain private fields (such as
``d`` or ``priv``) and can never be exported as a private JWK. The adapter
declares:

* the public key metadata,
* the set of JOSE algorithms the caller allows, and
* callbacks for the ``sign`` and ``unwrapKey`` private operations.

The JOSE header ``alg`` must be chosen from the allowed set declared on the
adapter; algorithms outside the set are rejected before any callback runs.
Callbacks receive exactly the input prescribed for the algorithm: the JWS
Signing Input for signatures, or the JWE Encrypted Key and headers for key
unwrapping. The returned signature is verified against the embedded public
key (which validates its length and encoding), and an unwrapped key must
have the expected length.

Signing example
---------------

.. code-block:: python

    from jwcrypto import jwk, jws
    from jwcrypto.externalkey import ExternalKeyAdapter

    # public_jwk is obtained from the hardware provider enrollment data
    adapter = ExternalKeyAdapter(
        public_jwk,
        sign_cb=my_hardware.sign,
        signing_algs=['RS256', 'PS256'],
    )

    jwsobj = jws.JWS(b'payload')
    jwsobj.add_signature(adapter, protected={'alg': 'RS256'})
    compact = jwsobj.serialize(compact=True)

    # Verifiers use the ordinary public key path
    verifier = jws.JWS()
    verifier.deserialize(compact, adapter.public_jwk())

The signing callback is invoked as
``sign_cb(alg, signing_input, headers, adapter)`` and must return the raw
signature bytes.

Key unwrapping example
----------------------

.. code-block:: python

    from jwcrypto import jwe
    from jwcrypto.externalkey import ExternalKeyAdapter

    adapter = ExternalKeyAdapter(
        public_jwk,
        unwrap_cb=my_hardware.unwrap,
        unwrapping_algs=['RSA-OAEP', 'RSA-OAEP-256'],
    )

    jweobj = jwe.JWE()
    jweobj.deserialize(compact_jwe, adapter)

The unwrap callback is invoked as
``unwrap_cb(alg, encrypted_key, headers, adapter)`` and must return the
unwrapped Content Encryption Key bytes.

Classes
-------

.. autoclass:: jwcrypto.externalkey.ExternalKeyAdapter
   :members:
   :show-inheritance:

Exceptions
----------

.. autoclass:: jwcrypto.externalkey.ExternalKeyError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.externalkey.InvalidExternalKeyConfig
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.externalkey.InvalidExternalKeyOperation
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.externalkey.ExternalKeyProviderError
   :members:
   :show-inheritance:

.. autoclass:: jwcrypto.externalkey.InvalidExternalKeyResponse
   :members:
   :show-inheritance:
