# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Explicit external key operation adapters.

This module provides an adapter for private keys that are not held by the
application, for example keys stored in an Hardware Security Module (HSM), a
Trusted Execution Environment or a remote signing service.  The application
can only obtain the public key as a regular :class:`jwcrypto.jwk.JWK`; the
private part cannot be exported.

Private key operations are therefore delegated to caller-provided
callbacks.  The adapter never fabricates a JWK containing private key
material (such as an RSA ``d`` parameter); it only records the public key
metadata together with the algorithms and operations the caller explicitly
allows.

Two private operations are supported:

* ``sign``       - produce a JWS signature for an asymmetric algorithm;
* ``unwrapKey``  - decrypt (unwrap) a JWE Content Encryption Key.

The adapter makes sure that:

* only algorithms declared by the caller are ever requested from a
  callback;
* the ``alg`` value of a JOSE header is in the caller's allow set;
* the ``use``/``key_ops`` metadata of the public JWK permits the operation
  (an encryption-only key cannot be used for signing, for example);
* the data passed to a callback is exactly the input mandated by the
  algorithm (the RFC 7515 JWS Signing Input, or the raw JWE Encrypted
  Key);
* the bytes returned by a callback have the type and length the algorithm
  requires.

Any unsupported algorithm or disallowed usage is rejected before the
callback is invoked.
"""

from collections import namedtuple

from jwcrypto.common import InvalidJWEKeyLength
from jwcrypto.common import InvalidJWEKeyType
from jwcrypto.common import JWException
from jwcrypto.common import base64url_decode
from jwcrypto.common import json_encode
from jwcrypto.jwk import JWK
from jwcrypto.jwk import InvalidJWKOperation, InvalidJWKUsage
from jwcrypto.jwk import InvalidJWKValue


class ExternalKeyError(JWException):
    """Base class for external key adapter errors."""


class ExternalKeyOperationRejected(ExternalKeyError):
    """A requested operation or algorithm is not allowed by the adapter.

    This exception is raised before any provider callback is invoked.
    """

    def __init__(self, message):
        super(ExternalKeyOperationRejected, self).__init__(message)


class ExternalKeyInvalidResponse(ExternalKeyError):
    """A provider callback returned a malformed or wrong-sized value.

    Raised after a callback runs, when its return value does not have the
    type, length and format required by the requested algorithm.
    """

    def __init__(self, message):
        super(ExternalKeyInvalidResponse, self).__init__(message)


# Fixed signature size, in bytes, of the raw (fixed length) signature
# produced by ECDSA (JOSE R || S encoding), EdDSA and ML-DSA algorithms.
_ES_CURVE_BYTES = {
    'P-256': 64,
    'P-384': 96,
    'P-521': 132,
    'secp256k1': 64,
    'BP-256': 64,
    'BP-384': 96,
    'BP-512': 132,
}

_ED_CURVE_BYTES = {
    'Ed25519': 64,
    'Ed448': 114,
}

# FIPS 204 signature sizes, in bytes.
_MLDSA_BYTES = {
    'ML-DSA-44': 2420,
    'ML-DSA-65': 3309,
    'ML-DSA-87': 4627,
}


def _fixed_sig_size(size):
    def length(_spec, _key):
        return size
    return length


def _rsa_sig_size(_spec, key):
    # RFC 8017: an RSA signature is k octets long, where k is the size
    # of the modulus in octets.
    return len(base64url_decode(key.get('n')))


def _es_sig_size(spec, _key):
    return _ES_CURVE_BYTES[spec.crv]


def _eddsa_sig_size(spec, key):
    return _ED_CURVE_BYTES[key.get('crv')]


def _mldsa_sig_size(spec, _key):
    return _MLDSA_BYTES[spec.alg_field]


# Description of a signature algorithm that can be executed externally.
#   kty       - the public JWK key type the algorithm requires
#   crv       - for EC/OKP keys, the required curve (or a tuple of
#               allowed curves), None otherwise
#   alg_field - for AKP keys, the required value of the JWK 'alg' field
#   length    - callable(spec, key) returning the required signature
#               length, in bytes
ExternalSigSpec = namedtuple(
    'ExternalSigSpec', 'kty crv alg_field length')


_EXTERNAL_SIG_ALGS = {
    'RS256': ExternalSigSpec(
        'RSA', None, None, _rsa_sig_size),
    'RS384': ExternalSigSpec(
        'RSA', None, None, _rsa_sig_size),
    'RS512': ExternalSigSpec(
        'RSA', None, None, _rsa_sig_size),
    'PS256': ExternalSigSpec(
        'RSA', None, None, _rsa_sig_size),
    'PS384': ExternalSigSpec(
        'RSA', None, None, _rsa_sig_size),
    'PS512': ExternalSigSpec(
        'RSA', None, None, _rsa_sig_size),
    'ES256': ExternalSigSpec(
        'EC', 'P-256', None, _es_sig_size),
    'ES384': ExternalSigSpec(
        'EC', 'P-384', None, _es_sig_size),
    'ES512': ExternalSigSpec(
        'EC', 'P-521', None, _es_sig_size),
    'ES256K': ExternalSigSpec(
        'EC', 'secp256k1', None, _es_sig_size),
    'BP256R1': ExternalSigSpec(
        'EC', 'BP-256', None, _es_sig_size),
    'BP384R1': ExternalSigSpec(
        'EC', 'BP-384', None, _es_sig_size),
    'BP512R1': ExternalSigSpec(
        'EC', 'BP-512', None, _es_sig_size),
    'EdDSA': ExternalSigSpec(
        'OKP', ('Ed25519', 'Ed448'), None, _eddsa_sig_size),
    'Ed25519': ExternalSigSpec(
        'OKP', 'Ed25519', None, _fixed_sig_size(64)),
    'Ed448': ExternalSigSpec(
        'OKP', 'Ed448', None, _fixed_sig_size(114)),
    'ML-DSA-44': ExternalSigSpec(
        'AKP', None, 'ML-DSA-44', _mldsa_sig_size),
    'ML-DSA-65': ExternalSigSpec(
        'AKP', None, 'ML-DSA-65', _mldsa_sig_size),
    'ML-DSA-87': ExternalSigSpec(
        'AKP', None, 'ML-DSA-87', _mldsa_sig_size),
}


# Description of a key management algorithm whose private operation
# (key decryption) can be executed externally.  Only asymmetric RSA key
# transport algorithms use the private key to unwrap a raw Encrypted Key;
# key agreement (ECDH-ES), direct and symmetric key wrap algorithms do not
# have a private-key unwrap operation of this shape.
ExternalUnwrapSpec = namedtuple(
    'ExternalUnwrapSpec', 'kty crv alg_field')

_EXTERNAL_UNWRAP_ALGS = {
    'RSA1_5': ExternalUnwrapSpec('RSA', None, None),
    'RSA-OAEP': ExternalUnwrapSpec('RSA', None, None),
    'RSA-OAEP-256': ExternalUnwrapSpec('RSA', None, None),
}

# Operations that a callback-based adapter may expose.
EXTERNAL_OPERATIONS = ('sign', 'unwrapKey')

# Maps a private operation to the equivalent public key operation which
# may appear in the public JWK 'key_ops' metadata.
_PUBLIC_OPERATION_PEER = {
    'sign': 'verify',
    'unwrapKey': 'wrapKey',
}

# Maps a private operation to the required JWK 'use' value.
_OPERATION_USE = {
    'sign': 'sig',
    'unwrapKey': 'enc',
}


class ExternalKey(object):
    """Adapter for a private key held by an external provider.

    The private key is never available to the application: only the
    public JWK metadata is retained.  Private key operations are executed
    by caller-supplied callbacks, which typically forward the request to a
    Hardware Security Module or a remote signing service.

    This is *not* a :class:`jwcrypto.jwk.JWK` and it never contains a
    private key value (such as the RSA ``d`` parameter).  Tokens produced
    through it can nonetheless be verified/decrypted by other parties
    using the regular public key JWK path.

    :param public_key: A public JWK.  It must be an asymmetric
     :class:`jwcrypto.jwk.JWK` that carries no private key value.
    :param algs: The list of algorithm names the caller permits for this
     key.  The ``alg`` of a JOSE header must be in this list.  Only
     algorithms the external operation model supports are accepted.
    :param signer: The signing callback.  It is invoked as
     ``signer(key, algorithm, signing_input)`` where ``key`` is this
     adapter, ``algorithm`` is the algorithm name and ``signing_input``
     is the bytes JWS Signing Input (RFC 7515, section 5.1).  It must
     return the signature as raw ``bytes``.  Required to enable the
     ``sign`` operation.
    :param unwrapper: The key unwrapping callback.  It is invoked as
     ``unwrapper(key, algorithm, encrypted_key, expected_bits)`` where
     ``encrypted_key`` is the raw JWE Encrypted Key bytes and
     ``expected_bits`` is the required Content Encryption Key size in
     bits.  It must return the unwrapped CEK as raw ``bytes``.  Required
     to enable the ``unwrapKey`` operation.
    :param operations: Optional explicit list of private operations this
     adapter exposes; values must be from
     :data:`EXTERNAL_OPERATIONS`.  By default the set is inferred from
     the callbacks provided.

    :raises InvalidJWKValue: if the constructor parameters are invalid.
    :raises ExternalKeyOperationRejected: if an algorithm is not
     supported for the enabled operations or does not match the public
     key metadata.
    """

    def __init__(self, public_key, algs, signer=None, unwrapper=None,
                 operations=None):
        if not isinstance(public_key, JWK):
            raise InvalidJWKValue('public_key must be a JWK object')
        if public_key.is_symmetric:
            raise InvalidJWKValue(
                'An external key must be an asymmetric public JWK')
        if public_key.has_private:
            raise InvalidJWKValue(
                'The public JWK must not contain private key values')

        if not isinstance(algs, (list, tuple)) or len(algs) == 0:
            raise InvalidJWKValue(
                'algs must be a non-empty list of algorithm names')
        if any(not isinstance(name, str) for name in algs):
            raise InvalidJWKValue('algs must contain only strings')
        if len(set(algs)) != len(algs):
            raise InvalidJWKValue('Duplicate values in algs')

        callbacks = {'sign': signer, 'unwrapKey': unwrapper}
        if operations is None:
            enabled = []
            for operation in EXTERNAL_OPERATIONS:
                if callbacks[operation] is not None:
                    enabled.append(operation)
            if not enabled:
                raise InvalidJWKValue(
                    'At least one of the signer or unwrapper '
                    'callbacks must be provided')
            enabled = tuple(enabled)
        else:
            if not isinstance(operations, (list, tuple)) or \
                    len(operations) == 0:
                raise InvalidJWKValue(
                    'operations must be a non-empty list')
            if len(set(operations)) != len(operations):
                raise InvalidJWKValue(
                    'Duplicate values in operations')
            enabled = []
            for operation in operations:
                if operation not in EXTERNAL_OPERATIONS:
                    raise InvalidJWKOperation(
                        operation, list(EXTERNAL_OPERATIONS))
                if callbacks[operation] is None:
                    raise InvalidJWKValue(
                        'No callback provided for operation "%s"'
                        % operation)
                enabled.append(operation)
            enabled = tuple(enabled)

        for operation in enabled:
            if not callable(callbacks[operation]):
                raise InvalidJWKValue(
                    'Callback for operation "%s" must be callable'
                    % operation)

        self._public_key = public_key
        self._algs = tuple(algs)
        self._operations = tuple(enabled)
        self._signer = signer
        self._unwrapper = unwrapper

        for name in algs:
            specs = []
            if 'sign' in enabled and name in _EXTERNAL_SIG_ALGS:
                specs.append(_EXTERNAL_SIG_ALGS[name])
            if 'unwrapKey' in enabled and name in _EXTERNAL_UNWRAP_ALGS:
                specs.append(_EXTERNAL_UNWRAP_ALGS[name])
            if not specs:
                raise ExternalKeyOperationRejected(
                    'Algorithm "%s" is not supported for the enabled '
                    'operations %s' % (
                        name, list(enabled)))
            for spec in specs:
                self._check_public_key_matches(public_key, name, spec)

    def _check_public_key_matches(self, key, algorithm, spec):
        if key.get('kty') != spec.kty:
            raise InvalidJWEKeyType(spec.kty, key.get('kty'))
        if spec.crv is not None:
            allowed = (spec.crv,) if isinstance(spec.crv, str) \
                else spec.crv
            if key.get('crv') not in allowed:
                raise ExternalKeyOperationRejected(
                    'Algorithm "%s" requires curve %s, public key curve '
                    'is "%s"' % (algorithm, list(allowed),
                                 key.get('crv')))
        if spec.alg_field is not None:
            if key.get('alg') != spec.alg_field:
                raise ExternalKeyOperationRejected(
                    'Algorithm "%s" requires a JWK "alg" value of "%s", '
                    'got "%s"' % (
                        algorithm, spec.alg_field, key.get('alg')))

    def _check_operation_permitted(self, operation):
        if operation not in self._operations:
            raise ExternalKeyOperationRejected(
                'Operation "%s" is not enabled on this external key; '
                'enabled operations: %s' % (
                    operation, list(self._operations)))

        # Enforce the public JWK usage metadata.
        key = self._public_key
        required_use = _OPERATION_USE[operation]
        use = key.get('use')
        if use is not None and use != required_use:
            raise InvalidJWKUsage(required_use, use)

        ops = key.get('key_ops')
        if ops is not None:
            if not isinstance(ops, list):
                ops = [ops]
            public_peer = _PUBLIC_OPERATION_PEER[operation]
            if operation not in ops and public_peer not in ops:
                raise InvalidJWKOperation(operation, ops)

    @staticmethod
    def _require_bytes(value, what):
        if not isinstance(value, bytes):
            raise ExternalKeyInvalidResponse(
                '%s must be raw bytes, got %s' % (
                    what, type(value).__name__))
        if len(value) == 0:
            raise ExternalKeyInvalidResponse('%s must not be empty' % what)

    def sign(self, algorithm, signing_input):
        """Produce a JWS signature through the external provider.

        The request is rejected before the callback is invoked if signing
        is not enabled, the algorithm is not in the caller's allow set,
        or the public key metadata does not permit signature use.

        :param algorithm: The signature algorithm name, taken from the
         JWS protected header.
        :param signing_input(bytes): The RFC 7515 JWS Signing Input,
         that is ``ASCII(BASE64URL(Protected Header)) || '.' ||
         BASE64URL(Payload)`` (or the raw payload for ``b64=false``).

        :raises ExternalKeyOperationRejected: if signing is not allowed.
        :raises InvalidJWKUsage: if the public key ``use`` forbids it.
        :raises InvalidJWKOperation: if the public key ``key_ops``
         forbids it.
        :raises ExternalKeyInvalidResponse: if the callback does not
         return a properly formatted signature of the required length.

        :return: The raw signature bytes in the format required by the
         algorithm (JOSE R || S encoding for ECDSA).
        :rtype: `bytes`
        """
        if algorithm not in self._algs:
            raise ExternalKeyOperationRejected(
                'Algorithm "%s" is not in the allowed set %s' % (
                    algorithm, list(self._algs)))
        spec = _EXTERNAL_SIG_ALGS.get(algorithm)
        if spec is None:
            raise ExternalKeyOperationRejected(
                'Algorithm "%s" cannot be used for external signing'
                % algorithm)
        self._check_operation_permitted('sign')
        self._check_public_key_matches(
            self._public_key, algorithm, spec)

        self._require_bytes(signing_input, 'signing input')

        signature = self._signer(self, algorithm, signing_input)
        self._require_bytes(signature, 'signature')

        expected_length = spec.length(spec, self._public_key)
        if len(signature) != expected_length:
            raise ExternalKeyInvalidResponse(
                'Invalid signature length for %s: expected %d bytes, '
                'got %d' % (
                    algorithm, expected_length, len(signature)))
        return signature

    def unwrap_key(self, algorithm, encrypted_key, expected_bits):
        """Unwrap a JWE Content Encryption Key through the provider.

        The request is rejected before the callback is invoked if key
        unwrapping is not enabled, the algorithm is not in the caller's
        allow set, or the public key metadata does not permit encryption
        use.

        :param algorithm: The key management algorithm name, taken from
         the JWE header.
        :param encrypted_key(bytes): The raw JWE Encrypted Key.
        :param expected_bits(int): The required CEK size in bits, as
         determined by the content encryption algorithm.

        :raises ExternalKeyOperationRejected: if unwrapping is not
         allowed.
        :raises InvalidJWKUsage: if the public key ``use`` forbids it.
        :raises InvalidJWKOperation: if the public key ``key_ops``
         forbids it.
        :raises InvalidJWKValue: if ``expected_bits`` is not a positive
         multiple of eight.
        :raises ExternalKeyInvalidResponse: if the callback does not
         return a CEK with the requested size.

        :return: The unwrapped Content Encryption Key bytes.
        :rtype: `bytes`
        """
        if algorithm not in self._algs:
            raise ExternalKeyOperationRejected(
                'Algorithm "%s" is not in the allowed set %s' % (
                    algorithm, list(self._algs)))
        spec = _EXTERNAL_UNWRAP_ALGS.get(algorithm)
        if spec is None:
            raise ExternalKeyOperationRejected(
                'Algorithm "%s" cannot be used for external key '
                'unwrapping' % algorithm)
        self._check_operation_permitted('unwrapKey')
        self._check_public_key_matches(
            self._public_key, algorithm, spec)

        self._require_bytes(encrypted_key, 'encrypted key')
        if not isinstance(expected_bits, int) or \
                isinstance(expected_bits, bool) or expected_bits <= 0 \
                or expected_bits % 8 != 0:
            raise InvalidJWKValue(
                'expected_bits must be a positive multiple of 8')

        cek = self._unwrapper(self, algorithm, encrypted_key,
                              expected_bits)
        self._require_bytes(cek, 'unwrapped key')
        if len(cek) * 8 != expected_bits:
            raise InvalidJWEKeyLength(expected_bits, len(cek) * 8)
        return cek

    @property
    def public_jwk(self):
        """The public JWK describing the externally held key."""
        return self._public_key

    @property
    def allowed_algs(self):
        """The tuple of algorithms the caller allowed for this key."""
        return self._algs

    @property
    def allowed_operations(self):
        """The tuple of private operations this adapter exposes."""
        return self._operations

    @property
    def kid(self):
        """The ``kid`` of the public key, if set."""
        return self._public_key.get('kid')

    def export_public_jwk(self, as_dict=False):
        """Exports the public key in the standard JWK format.

        No private material is ever exported, as this adapter does not
        hold any.
        """
        return self._public_key.export_public(as_dict)

    def __repr__(self):
        data = {
            'kid': self._public_key.get('kid', 'Missing Key ID'),
            'thumbprint': self._public_key.thumbprint(),
            'external_operations': list(self._operations),
            'algs': list(self._algs),
        }
        return json_encode(data)
