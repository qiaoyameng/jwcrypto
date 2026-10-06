# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Tests for the external key operation adapter (:mod:`jwcrypto.extkey`).

No real hardware SDK is involved: a local :class:`FakeHardwareProvider`
plays the role of the HSM/remote signer.  It holds the private keys
locally, records every call it receives and can be configured to reject
operations or return malformed values.
"""

import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from jwcrypto import jwe, jws, jwt
from jwcrypto.common import InvalidJWEKeyLength, InvalidJWEKeyType
from jwcrypto.extkey import EXTERNAL_OPERATIONS, ExternalKey
from jwcrypto.extkey import ExternalKeyInvalidResponse
from jwcrypto.extkey import ExternalKeyOperationRejected
from jwcrypto.jwa import JWA
from jwcrypto.jwk import JWK, InvalidJWKOperation, InvalidJWKUsage
from jwcrypto.jwk import InvalidJWKValue

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    MLDSA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on cryptography version
    MLDSA_AVAILABLE = False


class ProviderRejected(Exception):
    """Raised by the fake provider when it refuses an operation."""


class FakeHardwareProvider(object):
    """A local stand-in for an external signing/HSM service.

    Private keys are indexed by the public key thumbprint.  The provider
    records the parameters of every callback so tests can assert that the
    adapter forwards exactly the algorithm mandated input.
    """

    def __init__(self):
        self._private = {}
        self.calls = []
        # When set, the provider refuses signing for these algorithms.
        self.reject_sign_algs = set()
        # When True the next sign/unwrap response is replaced by a value
        # of the wrong type (non-bytes).
        self.sign_bad_type = False
        self.unwrap_bad_type = False
        # When set, the returned value is truncated/padded to this size.
        self.sign_force_length = None
        self.unwrap_force_length = None

    def enroll(self, private_jwk):
        """Registers a private JWK as held by the hardware."""
        if not private_jwk.has_private:
            raise ValueError('enroll() requires a private JWK')
        self._private[private_jwk.thumbprint()] = private_jwk
        return private_jwk.thumbprint()

    def _lookup(self, external_key):
        thumbprint = external_key.public_jwk.thumbprint()
        if thumbprint not in self._private:
            raise ProviderRejected('Unknown key')
        return self._private[thumbprint]

    def sign(self, external_key, algorithm, signing_input):
        """Signs the JWS Signing Input using the held private key."""
        if algorithm in self.reject_sign_algs:
            raise ProviderRejected(
                'Algorithm %s is not enabled for this key' % algorithm)

        private = self._lookup(external_key)
        self.calls.append({
            'op': 'sign',
            'alg': algorithm,
            'key': external_key,
            'input': signing_input,
        })

        signature = JWA.signing_alg(algorithm).sign(
            private, signing_input)
        if self.sign_bad_type:
            return 'not-bytes'
        if self.sign_force_length is not None:
            return signature[:self.sign_force_length]
        return signature

    def unwrap(self, external_key, algorithm, encrypted_key, expected_bits):
        """Decrypts the JWE Encrypted Key using the held private key."""
        private = self._lookup(external_key)
        self.calls.append({
            'op': 'unwrapKey',
            'alg': algorithm,
            'key': external_key,
            'input': encrypted_key,
            'expected_bits': expected_bits,
        })

        if algorithm == 'RSA1_5':
            pad = padding.PKCS1v15()
        elif algorithm == 'RSA-OAEP':
            pad = padding.OAEP(padding.MGF1(hashes.SHA1()),
                               hashes.SHA1(), None)
        else:  # RSA-OAEP-256
            pad = padding.OAEP(padding.MGF1(hashes.SHA256()),
                               hashes.SHA256(), None)
        cek = private._get_private_key().decrypt(encrypted_key, pad)
        if self.unwrap_bad_type:
            return 1234
        if self.unwrap_force_length is not None:
            return cek[:self.unwrap_force_length]
        return cek


def _external_sign_key(provider, private_jwk, algs=None):
    provider.enroll(private_jwk)
    algs = algs or ['RS256']
    return ExternalKey(private_jwk.public(), algs,
                       signer=provider.sign)


def _external_unwrap_key(provider, private_jwk, algs=None):
    provider.enroll(private_jwk)
    algs = algs or ['RSA-OAEP']
    return ExternalKey(private_jwk.public(), algs,
                       unwrapper=provider.unwrap)


class TestExternalSigning(unittest.TestCase):

    def _roundtrip(self, kty, alg, crv=None, header_alg=None,
                   jwk_alg=None):
        provider = FakeHardwareProvider()
        if jwk_alg is not None:
            priv = JWK.generate(kty=kty, alg=jwk_alg, kid='k')
        elif crv is not None:
            priv = JWK.generate(kty=kty, crv=crv, kid='k')
        else:
            priv = JWK.generate(kty=kty, kid='k')
        external = _external_sign_key(provider, priv, [alg])
        payload = b'hardware signed payload'
        token = jws.JWS(payload)
        token.add_signature(external,
                            protected={'alg': header_alg or alg})
        compact = token.serialize(compact=True)

        # The token must verify through the ordinary public JWK path.
        verifier = jws.JWS()
        verifier.deserialize(compact, priv.public())
        self.assertEqual(verifier.payload, payload)

        # The provider must have received the exact JWS Signing Input.
        self.assertEqual(len(provider.calls), 1)
        call = provider.calls[0]
        self.assertEqual(call['op'], 'sign')
        self.assertEqual(call['alg'], alg)
        self.assertIsInstance(call['input'], bytes)
        protected_b64, payload_b64, _ = compact.split('.')
        expected_input = (protected_b64 + '.' + payload_b64).encode()
        self.assertEqual(call['input'], expected_input)
        return compact

    def test_jws_rsa_roundtrip(self):
        self._roundtrip('RSA', 'RS256')
        self._roundtrip('RSA', 'PS256')

    def test_jws_ec_roundtrip(self):
        self._roundtrip('EC', 'ES256', 'P-256')
        self._roundtrip('EC', 'ES384', 'P-384')
        self._roundtrip('EC', 'ES512', 'P-521')
        self._roundtrip('EC', 'ES256K', 'secp256k1')

    def test_jws_okp_roundtrip(self):
        self._roundtrip('OKP', 'Ed25519', 'Ed25519')
        self._roundtrip('OKP', 'Ed448', 'Ed448')
        self._roundtrip('OKP', 'EdDSA', 'Ed25519')

    @unittest.skipUnless(MLDSA_AVAILABLE,
                         'ML-DSA requires cryptography >= 49')
    def test_jws_mldsa_roundtrip(self):
        self._roundtrip('AKP', 'ML-DSA-44', jwk_alg='ML-DSA-44')

    def test_jwt_roundtrip(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048, kid='jwtkey')
        external = _external_sign_key(provider, priv, ['RS256'])

        signed = jwt.JWT(header={'alg': 'RS256'},
                         claims={'sub': 'hardware'},
                         default_claims={})
        signed.make_signed_token(external)
        token = signed.token.serialize(compact=True)

        validated = jwt.JWT(jwt=token, key=priv.public(),
                            default_claims={})
        self.assertEqual(validated.claims, '{"sub":"hardware"}')
        self.assertEqual(provider.calls[0]['alg'], 'RS256')

    def test_header_alg_must_be_allowed_by_caller(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        # The caller only authorizes ES256-style restrictions: here the
        # adapter only lists RS256, so an RS384 header must be rejected.
        external = _external_sign_key(provider, priv, ['RS256'])
        token = jws.JWS(b'p')
        with self.assertRaises(ExternalKeyOperationRejected):
            token.add_signature(external, protected={'alg': 'RS384'})
        # The callback is never reached.
        self.assertEqual(provider.calls, [])

    def test_jws_allowed_algs_still_gates_header(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_sign_key(
            provider, priv, ['RS256', 'RS384'])
        token = jws.JWS(b'p')
        token.allowed_algs = ['RS256']
        with self.assertRaises(Exception):
            token.add_signature(external, protected={'alg': 'RS384'})

    def test_verify_rejects_external_key(self):
        # The adapter is a signing handle, not a verification key.
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048, kid='k')
        external = _external_sign_key(provider, priv, ['RS256'])
        token = jws.JWS(b'p')
        token.add_signature(external, protected={'alg': 'RS256'})
        compact = token.serialize(compact=True)

        verifier = jws.JWS()
        with self.assertRaises(jws.InvalidJWSSignature):
            verifier.deserialize(compact, external)


class TestExternalKeyRejections(unittest.TestCase):

    def test_provider_rejected_operation_propagates(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_sign_key(provider, priv, ['RS256'])
        provider.reject_sign_algs.add('RS256')

        with self.assertRaises(ProviderRejected):
            external.sign('RS256', b'\x00\x01signing input')

        # The call did reach the provider (policy enforced remotely),
        # but it refused before recording it.
        self.assertEqual(provider.calls, [])

    def test_provider_rejection_through_jws_path(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_sign_key(provider, priv, ['RS256'])
        provider.reject_sign_algs.add('RS256')

        token = jws.JWS(b'p')
        with self.assertRaises(ProviderRejected):
            token.add_signature(external, protected={'alg': 'RS256'})

    def test_bad_signature_wrong_length(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='EC', crv='P-256')
        external = _external_sign_key(provider, priv, ['ES256'])
        provider.sign_force_length = 63  # ES256 requires 64 bytes

        with self.assertRaises(ExternalKeyInvalidResponse):
            external.sign('ES256', b'signing input')
        # The malformed response must not become a JWS.
        token = jws.JWS(b'p')
        provider.sign_force_length = 10
        with self.assertRaises(ExternalKeyInvalidResponse):
            token.add_signature(external, protected={'alg': 'ES256'})

    def test_bad_signature_wrong_type(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_sign_key(provider, priv, ['RS256'])
        provider.sign_bad_type = True
        with self.assertRaises(ExternalKeyInvalidResponse):
            external.sign('RS256', b'signing input')

    def test_sign_rejects_non_bytes_input(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_sign_key(provider, priv, ['RS256'])
        with self.assertRaises(ExternalKeyInvalidResponse):
            external.sign('RS256', 'not bytes')
        self.assertEqual(provider.calls, [])

    def test_enc_use_key_cannot_sign(self):
        # An encryption-purpose public key must be rejected for signing.
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        public = priv.public()
        public['use'] = 'enc'
        provider.enroll(priv)
        external = ExternalKey(public, ['RS256', 'RSA-OAEP'],
                               signer=provider.sign,
                               unwrapper=provider.unwrap)
        with self.assertRaises(InvalidJWKUsage):
            external.sign('RS256', b'signing input')
        self.assertEqual(provider.calls, [])

    def test_key_ops_enc_key_cannot_sign(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        public = priv.public()
        public['key_ops'] = ['wrapKey']
        provider.enroll(priv)
        external = ExternalKey(public, ['RS256', 'RSA-OAEP'],
                               signer=provider.sign,
                               unwrapper=provider.unwrap)
        with self.assertRaises(InvalidJWKOperation):
            # Signing is enabled on the adapter but the public key
            # metadata only advertises encryption operations.
            external.sign('RS256', b'signing input')
        self.assertEqual(provider.calls, [])

    def test_sign_operation_not_enabled(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_unwrap_key(provider, priv, ['RSA-OAEP'])
        with self.assertRaises(ExternalKeyOperationRejected):
            external.sign('RSA-OAEP', b'signing input')

    def test_algorithm_not_in_allow_set_rejected_before_call(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_sign_key(provider, priv, ['RS256'])
        with self.assertRaises(ExternalKeyOperationRejected):
            external.sign('PS256', b'signing input')
        self.assertEqual(provider.calls, [])

    def test_symmetric_algorithm_unsupported(self):
        # HMAC algorithms have no asymmetric external key operation.
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        provider.enroll(priv)
        with self.assertRaises(ExternalKeyOperationRejected):
            ExternalKey(priv.public(), ['HS256'],
                        signer=provider.sign)

    def test_unsupported_algorithm_for_operation(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        provider.enroll(priv)
        with self.assertRaises(ExternalKeyOperationRejected):
            ExternalKey(priv.public(), ['RS256'],
                        unwrapper=provider.unwrap)

    def test_algorithm_key_type_mismatch(self):
        provider = FakeHardwareProvider()
        ec_priv = JWK.generate(kty='EC', crv='P-256')
        provider.enroll(ec_priv)
        with self.assertRaises(InvalidJWEKeyType):
            ExternalKey(ec_priv.public(), ['RS256'],
                        signer=provider.sign)

    def test_algorithm_curve_mismatch(self):
        provider = FakeHardwareProvider()
        ec_priv = JWK.generate(kty='EC', crv='P-384')
        provider.enroll(ec_priv)
        with self.assertRaises(ExternalKeyOperationRejected):
            ExternalKey(ec_priv.public(), ['ES256'],
                        signer=provider.sign)


class TestExternalKeyUnwrap(unittest.TestCase):

    def _jwe_roundtrip(self, alg, enc='A128GCM', expected_bits=128):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048, kid='hmkey')
        external = _external_unwrap_key(provider, priv, [alg])
        plaintext = b'wrapped key plaintext'

        # Encryption uses the ordinary public key path.
        token = jwe.JWE(plaintext,
                        protected={'alg': alg, 'enc': enc})
        token.add_recipient(priv.public())
        compact = token.serialize(compact=True)

        # Decryption goes through the external unwrap callback.
        decrypted = jwe.JWE()
        decrypted.deserialize(compact, external)
        self.assertEqual(decrypted.payload, plaintext)

        self.assertEqual(len(provider.calls), 1)
        call = provider.calls[0]
        self.assertEqual(call['op'], 'unwrapKey')
        self.assertEqual(call['alg'], alg)
        self.assertIsInstance(call['input'], bytes)
        self.assertGreater(len(call['input']), 0)
        self.assertEqual(call['expected_bits'], expected_bits)

        parts = compact.split('.')
        from jwcrypto.common import base64url_decode
        self.assertEqual(call['input'],
                         base64url_decode(parts[1]))

    def test_jwe_oaep_roundtrip(self):
        self._jwe_roundtrip('RSA-OAEP')

    def test_jwe_oaep256_roundtrip(self):
        self._jwe_roundtrip('RSA-OAEP-256', enc='A256GCM',
                            expected_bits=256)

    def test_jwe_oaep_cbc_roundtrip(self):
        self._jwe_roundtrip('RSA-OAEP', enc='A128CBC-HS256',
                            expected_bits=256)

    def test_unwrap_provider_rejection(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_unwrap_key(provider, priv, ['RSA-OAEP'])

        def reject(_key, _alg, _ek, _bits):
            raise ProviderRejected('HSM unavailable')
        external._unwrapper = reject

        token = jwe.JWE(b'data',
                        protected={'alg': 'RSA-OAEP',
                                   'enc': 'A128GCM'})
        token.add_recipient(priv.public())
        decrypted = jwe.JWE()
        with self.assertRaises(jwe.InvalidJWEData):
            decrypted.deserialize(token.serialize(compact=True),
                                  external)

    def test_unwrap_bad_cek_length(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_unwrap_key(provider, priv, ['RSA-OAEP'])

        def short_cek(_key, _alg, _ek, bits):
            return b'\x00' * (bits // 8 - 8)

        external._unwrapper = short_cek
        with self.assertRaises(InvalidJWEKeyLength):
            external.unwrap_key(
                'RSA-OAEP', b'encrypted-key-bytes', 128)

    def test_unwrap_bad_cek_type(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_unwrap_key(provider, priv, ['RSA-OAEP'])

        # A real RSA-OAEP ciphertext produced by the public path; only
        # the provider's return value is tampered with.
        token = jwe.JWE(b'data',
                        protected={'alg': 'RSA-OAEP',
                                   'enc': 'A128GCM'})
        token.add_recipient(priv.public())
        from jwcrypto.common import base64url_decode
        encrypted_key = base64url_decode(
            token.serialize(compact=True).split('.')[1])
        provider.unwrap_bad_type = True

        with self.assertRaises(ExternalKeyInvalidResponse):
            external.unwrap_key('RSA-OAEP', encrypted_key, 128)

    def test_unwrap_rejects_non_bytes_input(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_unwrap_key(provider, priv, ['RSA-OAEP'])
        with self.assertRaises(ExternalKeyInvalidResponse):
            external.unwrap_key('RSA-OAEP', 4242, 128)
        self.assertEqual(provider.calls, [])

    def test_unwrap_rejects_bad_expected_bits(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_unwrap_key(provider, priv, ['RSA-OAEP'])
        for bad in (0, -128, 100, '128', 12.8):
            with self.assertRaises(InvalidJWKValue):
                external.unwrap_key('RSA-OAEP', b'ek', bad)
        self.assertEqual(provider.calls, [])

    def test_sig_use_key_cannot_unwrap(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        public = priv.public()
        public['use'] = 'sig'
        provider.enroll(priv)
        external = ExternalKey(public, ['RSA-OAEP'],
                               unwrapper=provider.unwrap)
        with self.assertRaises(InvalidJWKUsage):
            external.unwrap_key('RSA-OAEP', b'ek', 128)
        self.assertEqual(provider.calls, [])

    def test_key_ops_sig_key_cannot_unwrap(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        public = priv.public()
        public['key_ops'] = ['verify']
        provider.enroll(priv)
        external = ExternalKey(public, ['RSA-OAEP'],
                               signer=provider.sign,
                               unwrapper=provider.unwrap)
        with self.assertRaises(InvalidJWKOperation):
            external.unwrap_key('RSA-OAEP', b'ek', 128)
        self.assertEqual(provider.calls, [])

    def test_unwrap_algorithm_not_allowed(self):
        provider = FakeHardwareProvider()
        priv = JWK.generate(kty='RSA', size=2048)
        external = _external_unwrap_key(provider, priv, ['RSA-OAEP'])
        with self.assertRaises(ExternalKeyOperationRejected):
            external.unwrap_key('RSA-OAEP-256', b'ek', 128)
        self.assertEqual(provider.calls, [])


class TestExternalKeyMetadata(unittest.TestCase):

    def test_constructor_rejects_private_jwk(self):
        priv = JWK.generate(kty='RSA', size=2048)
        with self.assertRaises(InvalidJWKValue):
            ExternalKey(priv, ['RS256'], signer=lambda *a: b'')

    def test_constructor_rejects_symmetric_jwk(self):
        symmetric = JWK.generate(kty='oct', size=256)
        with self.assertRaises(InvalidJWKValue):
            ExternalKey(symmetric, ['HS256'], signer=lambda *a: b'')

    def test_constructor_rejects_non_jwk(self):
        with self.assertRaises(InvalidJWKValue):
            ExternalKey({'kty': 'RSA'}, ['RS256'],
                        signer=lambda *a: b'')

    def test_constructor_validates_algs(self):
        priv = JWK.generate(kty='RSA', size=2048)
        pub = priv.public()
        with self.assertRaises(InvalidJWKValue):
            ExternalKey(pub, [], signer=lambda *a: b'')
        with self.assertRaises(InvalidJWKValue):
            ExternalKey(pub, ['RS256', 'RS256'],
                        signer=lambda *a: b'')
        with self.assertRaises(InvalidJWKValue):
            ExternalKey(pub, [42], signer=lambda *a: b'')

    def test_constructor_requires_matching_callback(self):
        priv = JWK.generate(kty='RSA', size=2048)
        with self.assertRaises(InvalidJWKValue):
            ExternalKey(priv.public(), ['RS256'])
        # An explicit operation without a matching callback is also
        # invalid, even when another callback is present.
        with self.assertRaises(InvalidJWKOperation):
            ExternalKey(priv.public(), ['RS256'],
                        operations=['bogus'],
                        signer=lambda *a: b'')
        with self.assertRaises(InvalidJWKValue):
            ExternalKey(priv.public(), ['RS256'],
                        operations=['sign', 'unwrapKey'],
                        signer=lambda *a: b'')

    def test_operations_inferred_from_callbacks(self):
        priv = JWK.generate(kty='RSA', size=2048)
        external = ExternalKey(
            priv.public(), ['RS256', 'RSA-OAEP'],
            signer=lambda *a: b'', unwrapper=lambda *a: b'')
        self.assertEqual(set(external.allowed_operations),
                         set(EXTERNAL_OPERATIONS))

    def test_not_a_jwk_and_no_private_export(self):
        priv = JWK.generate(kty='RSA', size=2048)
        external = ExternalKey(priv.public(), ['RS256'],
                               signer=lambda *a: b'')
        self.assertNotIsInstance(external, JWK)
        exported = external.export_public_jwk(as_dict=True)
        self.assertNotIn('d', exported)
        self.assertEqual(exported['kty'], 'RSA')
        # The adapter exposes metadata, never private key values.
        self.assertEqual(external.public_jwk, priv.public())
        self.assertIn('RS256', external.allowed_algs)


if __name__ == '__main__':
    unittest.main()
