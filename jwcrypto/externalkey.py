# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""External private key operation adapters.

This module provides an explicit integration point for hardware security
modules, key vaults, and similar providers that hold the private part of
an asymmetric key and never allow it to be exported.

An :class:`ExternalKeyAdapter` carries only the *public* key metadata as a
standard :class:`jwcrypto.jwk.JWK` and declares:

* the JOSE algorithms the caller is willing to use with the key, and
* explicit callbacks for the private operations ('sign' and 'unwrapKey').

Private material never appears in the adapter: it is not a :class:`JWK`
subclass and cannot be serialized as a key containing 'd'. The JWS/JWE
engines recognize the adapter and route the public-key operations through
the embedded JWK while delegating private operations to the callbacks.
"""

from cryptography.exceptions import InvalidSignature

from jwcrypto.common import InvalidJWEKeyLength
from jwcrypto.common import JWException
from jwcrypto.jwa import JWA
from jwcrypto.jwk import (
    JWK,
    ImplementedAKPAlgorithms,
    JWKOpAndUsePairs,
    JWKOperationsRegistry,
    JWKUseRegistry,
)


class ExternalKeyError(JWException):
    """Base class for external key adapter errors."""


class InvalidExternalKeyConfig(ExternalKeyError):
    """Invalid adapter configuration.

    Raised when the adapter is constructed with an invalid public key,
    mismatched callbacks/algorithm lists, or an algorithm that is not
    supported for the declared key.
    """


class InvalidExternalKeyOperation(ExternalKeyError):
    """An external key operation cannot be performed.

    Raised, before any provider callback is invoked, when the requested
    algorithm is not in the caller's allowed set, the key does not permit
    the operation, or no callback was registered for it.
    """


class ExternalKeyProviderError(ExternalKeyError):
    """A provider explicitly refused an operation.

    Provider implementations raise this (or any exception) from a callback
    to signal that the external service denied the request; it is allowed
    to propagate unchanged.
    """


class InvalidExternalKeyResponse(ExternalKeyError):
    """The value returned by a provider callback is invalid.

    Raised when a signature is not a byte string, fails verification with
    the embedded public key, or an unwrapped key has the wrong size.
    """


# Requirements per supported algorithm: (accepted kty, accepted curves).
# Curves are only enforced for EC/OKP keys; None means "any curve".
_SIG_ALG_REQUIREMENTS = {
    'RS256': (('RSA',), None),
    'RS384': (('RSA',), None),
    'RS512': (('RSA',), None),
    'PS256': (('RSA',), None),
    'PS384': (('RSA',), None),
    'PS512': (('RSA',), None),
    'ES256': (('EC',), ('P-256',)),
    'ES256K': (('EC',), ('secp256k1',)),
    'ES384': (('EC',), ('P-384',)),
    'ES512': (('EC',), ('P-521',)),
    'BP256R1': (('EC',), ('BP-256',)),
    'BP384R1': (('EC',), ('BP-384',)),
    'BP512R1': (('EC',), ('BP-512',)),
    'EdDSA': (('OKP',), ('Ed25519', 'Ed448')),
    'Ed25519': (('OKP',), ('Ed25519',)),
    'Ed448': (('OKP',), ('Ed448',)),
}
for _alg in ImplementedAKPAlgorithms:
    _SIG_ALG_REQUIREMENTS[_alg] = (('AKP',), None)

# Key unwrapping (JWE 'alg') requirements. ECDH-ES derives the CEK on an EC
# or X-curve OKP key.
_UNWRAP_ALG_REQUIREMENTS = {
    'RSA1_5': (('RSA',), None),
    'RSA-OAEP': (('RSA',), None),
    'RSA-OAEP-256': (('RSA',), None),
    'ECDH-ES': (('EC', 'OKP'), None),
    'ECDH-ES+A128KW': (('EC', 'OKP'), None),
    'ECDH-ES+A192KW': (('EC', 'OKP'), None),
    'ECDH-ES+A256KW': (('EC', 'OKP'), None),
}


def _key_matches_requirement(jwk, alg_name, requirements):
    kty, curves = requirements
    if jwk.get('kty') not in kty:
        return False
    if curves is not None:
        if jwk.get('kty') in ('EC', 'OKP') and jwk.get('crv') not in curves:
            return False
    if jwk.get('kty') == 'AKP' and jwk.get('alg') != alg_name:
        return False
    return True


def _check_jwk_constraints(jwk, operation):
    """Validate 'use'/'key_ops' constraints like JWK.get_op_key does."""
    if operation not in JWKOperationsRegistry:
        raise InvalidExternalKeyOperation(
            'Unknown key operation: %s' % operation)
    usage = JWKOpAndUsePairs[operation]
    use = jwk.get('use')
    if use is not None and use != usage:
        valid = JWKUseRegistry.get(use, use)
        raise InvalidExternalKeyOperation(
            'Key use "%s" does not permit "%s"' % (valid, operation))
    key_ops = jwk.get('key_ops')
    if key_ops:
        if not isinstance(key_ops, list):
            key_ops = [key_ops]
        if operation not in key_ops:
            raise InvalidExternalKeyOperation(
                'Operation "%s" not in key_ops %s' % (operation, key_ops))


def _normalize_public(jwk):
    """Return a copy of jwk without usage/key_ops constraint fields.

    The normalized copy is used for internal public-key operations so that
    declared private constraints (e.g. key_ops=['sign']) cannot block the
    matching public operation. The 'alg' field is retained as it is part
    of the key material for some key types (e.g. AKP/ML-DSA).
    """
    copy_kwargs = {name: jwk[name] for name in jwk
                   if name not in ('use', 'key_ops')}
    return JWK(**copy_kwargs)


def _default_algs(jwk, requirements):
    """Return all supported requirements that match the given public key."""
    return [name for name, spec in requirements.items()
            if _key_matches_requirement(jwk, name, spec)]


class ExternalKeyAdapter(object):
    """Adapter for a private key held by an external provider.

    The adapter exposes only public key metadata and delegates private key
    operations ('sign' and 'unwrapKey') to caller provided callbacks.

    :param public_jwk: A :class:`jwcrypto.jwk.JWK` containing only the
        public part of the key; it must be an asymmetric key and must not
        carry private fields (e.g. 'd' or 'priv').
    :param sign_cb: Optional callback invoked as
        ``sign_cb(alg, signing_input, headers, adapter)`` to produce a JWS
        signature.
    :param signing_algs: Optional list of JWS 'alg' values the caller
        permits. Defaults to all supported algorithms matching the key type.
    :param unwrap_cb: Optional callback invoked as
        ``unwrap_cb(alg, encrypted_key, headers, adapter)`` to unwrap a JWE
        Content Encryption Key.
    :param unwrapping_algs: Optional list of JWE key management 'alg'
        values the caller permits. Defaults to all supported algorithms
        matching the key type.

    :raises InvalidExternalKeyConfig: if the parameters are inconsistent
        or describe an unsupported combination.
    """

    def __init__(self, public_jwk,
                 sign_cb=None, signing_algs=None,
                 unwrap_cb=None, unwrapping_algs=None):
        if not isinstance(public_jwk, JWK):
            raise InvalidExternalKeyConfig(
                'public_jwk must be a jwcrypto.jwk.JWK object')
        if public_jwk.is_symmetric:
            raise InvalidExternalKeyConfig(
                'External key adapters require an asymmetric public JWK')
        if public_jwk.has_private:
            raise InvalidExternalKeyConfig(
                'public_jwk must not contain private key material')
        if not public_jwk.has_public:
            raise InvalidExternalKeyConfig('No public key data provided')

        self._jwk = public_jwk
        self._verify_jwk = _normalize_public(public_jwk)
        self.sign_cb = sign_cb
        self.unwrap_cb = unwrap_cb

        if sign_cb is not None and signing_algs is None:
            signing_algs = _default_algs(self._jwk, _SIG_ALG_REQUIREMENTS)
        if unwrap_cb is not None and unwrapping_algs is None:
            unwrapping_algs = _default_algs(self._jwk,
                                            _UNWRAP_ALG_REQUIREMENTS)
        if sign_cb is None and signing_algs is not None:
            raise InvalidExternalKeyConfig(
                'signing_algs requires a sign_cb callback')
        if unwrap_cb is None and unwrapping_algs is not None:
            raise InvalidExternalKeyConfig(
                'unwrapping_algs requires an unwrap_cb callback')

        self.signing_algs = self._validate_alg_set(
            signing_algs, _SIG_ALG_REQUIREMENTS, JWA.signing_alg,
            sign_cb, 'signing')
        self.unwrapping_algs = self._validate_alg_set(
            unwrapping_algs, _UNWRAP_ALG_REQUIREMENTS, JWA.keymgmt_alg,
            unwrap_cb, 'unwrapping')

    @property
    def jwk(self):
        """The embedded public :class:`jwcrypto.jwk.JWK`."""
        return self._jwk

    def public_jwk(self):
        """Return a new :class:`jwcrypto.jwk.JWK` with public data only."""
        return JWK(**self._jwk.export_public(as_dict=True))

    def _validate_alg_set(self, algs, requirements, resolver,
                          callback, label):
        if callback is None:
            return []
        if algs is None:
            raise InvalidExternalKeyConfig(
                'No %s algorithms declared' % label)
        if not algs:
            raise InvalidExternalKeyConfig(
                'No %s algorithms declared' % label)

        validated = []
        for alg in algs:
            if alg not in requirements:
                raise InvalidExternalKeyConfig(
                    'Algorithm %s is not supported for external key %s'
                    % (alg, label))
            try:
                resolver(alg)
            except Exception as e:  # pylint: disable=broad-except
                raise InvalidExternalKeyConfig(
                    'Algorithm %s is not available: %s' % (alg, e)) from e
            if not _key_matches_requirement(
                    self._jwk, alg, requirements[alg]):
                raise InvalidExternalKeyConfig(
                    'Algorithm %s cannot be used with this key' % alg)
            validated.append(alg)
        return validated

    def get(self, name, default=None):
        """Access a metadata field of the embedded public key."""
        return self._jwk.get(name, default)

    def __getitem__(self, name):
        return self._jwk[name]

    def __contains__(self, name):
        return name in self._jwk

    def thumbprint(self):
        return self._jwk.thumbprint()

    def __repr__(self):
        return ('ExternalKeyAdapter(kid=%r, kty=%r, signing_algs=%r, '
                'unwrapping_algs=%r)' % (
                    self._jwk.get('kid'), self._jwk.get('kty'),
                    self.signing_algs, self.unwrapping_algs))

    def _prepare(self, alg, allowed, operation, callback):
        if alg not in allowed:
            raise InvalidExternalKeyOperation(
                'Algorithm %s is not in the allowed set %s'
                % (alg, allowed))
        _check_jwk_constraints(self._jwk, operation)
        if callback is None:
            raise InvalidExternalKeyOperation(
                'No callback registered for operation %s' % operation)

    def sign(self, alg, signing_input, headers=None):
        """Produce a signature through the external provider.

        :param alg: The JWS 'alg' value; it must be in ``signing_algs``.
        :param signing_input(bytes): The exact JWS Signing Input as defined
            by RFC 7515 (the bytes that the algorithm signs).
        :param headers: The merged JOSE header, passed to the callback.

        :return: The signature bytes.
        :raises InvalidExternalKeyOperation: if the algorithm/use is not
            permitted or no signing callback exists.
        :raises InvalidExternalKeyResponse: if the callback returns a
            non-bytes value or a signature that does not verify with the
            public key.
        """
        self._prepare(alg, self.signing_algs, 'sign', self.sign_cb)
        if not isinstance(signing_input, (bytes, bytearray)):
            raise InvalidExternalKeyOperation(
                'signing_input must be bytes')
        signature = self.sign_cb(alg, bytes(signing_input), headers, self)
        if not isinstance(signature, (bytes, bytearray)):
            raise InvalidExternalKeyResponse(
                'sign callback must return bytes, got %s'
                % type(signature).__name__)
        signature = bytes(signature)

        # Validate length/format by running the standard public key path.
        try:
            JWA.signing_alg(alg).verify(
                self._verify_jwk, bytes(signing_input), signature)
        except InvalidSignature as e:
            raise InvalidExternalKeyResponse(
                'External signature failed public key verification') from e
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidExternalKeyResponse(
                'External signature is malformed: %s' % e) from e
        return signature

    def unwrap(self, alg, encrypted_key, bitsize, headers=None):
        """Unwrap a Content Encryption Key through the external provider.

        :param alg: The JWE key management 'alg' value; it must be in
            ``unwrapping_algs``.
        :param encrypted_key(bytes): The JWE Encrypted Key (may be empty
            for direct-agreement algorithms).
        :param bitsize(int): The expected unwrapped key length in bits.
        :param headers: The merged JOSE header, passed to the callback.

        :return: The unwrapped key bytes.
        :raises InvalidExternalKeyOperation: if the algorithm/use is not
            permitted or no unwrap callback exists.
        :raises InvalidExternalKeyResponse: if the callback returns a
            non-bytes value or a key of the wrong length.
        """
        self._prepare(alg, self.unwrapping_algs, 'unwrapKey', self.unwrap_cb)
        if not isinstance(encrypted_key, (bytes, bytearray)):
            raise InvalidExternalKeyOperation(
                'encrypted_key must be bytes')
        cek = self.unwrap_cb(alg, bytes(encrypted_key), headers, self)
        if not isinstance(cek, (bytes, bytearray)):
            raise InvalidExternalKeyResponse(
                'unwrap callback must return bytes, got %s'
                % type(cek).__name__)
        cek = bytes(cek)
        if len(cek) * 8 != bitsize:
            raise InvalidJWEKeyLength(bitsize, len(cek) * 8)
        return cek
