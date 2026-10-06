# Copyright (C) 2026 JWCrypto Project Contributors - see LICENSE file

"""Tests for the external key operation adapter.

A local fake provider stands in for a hardware security module: it keeps
the private key in-process (but never hands it to jwcrypto), records every
callback invocation, and can be configured to refuse calls or return bad
values.
"""

import pytest

from jwcrypto import jwk, jwe, jws, jwt
from jwcrypto.common import InvalidJWEKeyLength, json_decode
from jwcrypto.externalkey import (
    ExternalKeyAdapter,
    InvalidExternalKeyConfig,
    InvalidExternalKeyOperation,
    ExternalKeyProviderError,
    InvalidExternalKeyResponse,
)


class FakeProvider:
    """Local stand-in for an external (hardware) key provider.

    It owns a private JWK and never exports it; jwcrypto only ever sees the
    matching public key through the adapter.
    """

    def __init__(self, private_jwk, refuse=False, bad_signature=False,
                 bad_cek=None):
        self._private = private_jwk
        self.refuse = refuse
        self.bad_signature = bad_signature
        self.bad_cek = bad_cek
        self.calls = []

    def public_jwk(self):
        return self._private.public()

    def _record(self, op, alg, data, headers):
        self.calls.append({'op': op, 'alg': alg, 'data': data,
                           'headers': dict(headers) if headers else {}})

    def sign_cb(self, alg, signing_input, headers, adapter):
        self._record('sign', alg, signing_input, headers)
        if self.refuse:
            raise ExternalKeyProviderError('signing disabled by policy')
        from jwcrypto.jwa import JWA
        sig = JWA.signing_alg(alg).sign(self._private, signing_input)
        if self.bad_signature:
            sig = b'not a valid signature'
        return sig

    def unwrap_cb(self, alg, encrypted_key, headers, adapter):
        self._record('unwrap', alg, encrypted_key, headers)
        if self.refuse:
            raise ExternalKeyProviderError('unwrap disabled by policy')
        from jwcrypto.jwa import JWA
        cek = JWA.keymgmt_alg(alg).unwrap(
            self._private, 256, encrypted_key, headers)
        if self.bad_cek is not None:
            cek = self.bad_cek
        return cek


def _adapter(private_jwk, provider=None, **kwargs):
    if provider is None:
        provider = FakeProvider(private_jwk)
    kw = {}
    if kwargs.pop('sign', True):
        kw['sign_cb'] = provider.sign_cb
    if kwargs.pop('unwrap', False):
        kw['unwrap_cb'] = provider.unwrap_cb
    kw.update(kwargs)
    return ExternalKeyAdapter(private_jwk.public(), **kw), provider


def test_rsa_jws_signed_by_provider_verifies_with_public_path():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    adapter, provider = _adapter(key, signing_algs=['RS256'])

    token = jws.JWS(b'protected payload')
    token.add_signature(
        adapter, protected={'alg': 'RS256', 'kid': 'hardware-key'})

    # The adapter is not a JWK and exposes no private material.
    assert not isinstance(adapter, jwk.JWK)
    with pytest.raises(Exception):
        adapter.public_jwk().export_private()
    assert 'd' not in json_decode(adapter.public_jwk().export())

    raw = token.serialize(compact=True)
    verifier = jws.JWS()
    verifier.deserialize(raw, adapter.public_jwk())
    assert verifier.is_valid

    # The callback received the exact RFC 7515 signing input.
    assert len(provider.calls) == 1
    call = provider.calls[0]
    assert call['op'] == 'sign'
    assert call['alg'] == 'RS256'
    protected, payload, signature = raw.split('.')
    signing_input = (protected + '.' + payload).encode('ascii')
    assert call['data'] == signing_input
    assert call['headers'] == {'alg': 'RS256', 'kid': 'hardware-key'}


def test_ec_jws_signing_input_and_verification():
    key = jwk.JWK.generate(kty='EC', crv='P-256')
    adapter, provider = _adapter(key, signing_algs=['ES256'])

    token = jws.JWS(b'ec payload')
    token.add_signature(adapter, alg='ES256', protected={'alg': 'ES256'})
    raw = token.serialize(compact=True)

    verifier = jws.JWS()
    verifier.deserialize(raw, adapter.jwk)
    assert verifier.is_valid

    call = provider.calls[0]
    protected, payload, _ = raw.split('.')
    assert call['data'] == (protected + '.' + payload).encode('ascii')


def test_jwt_roundtrip():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    adapter, _ = _adapter(key, signing_algs=['PS256'])

    token = jwt.JWT(header={'alg': 'PS256'}, claims={'hello': 'world'})
    token.make_signed_token(adapter)
    compact = token.serialize()

    parsed = jwt.JWT(key=adapter.public_jwk(), jwt=compact)
    assert json_decode(parsed.claims) == {'hello': 'world'}


def test_jwe_jwt_roundtrip():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    provider = FakeProvider(key)
    adapter = ExternalKeyAdapter(
        key.public(), unwrap_cb=provider.unwrap_cb,
        unwrapping_algs=['RSA-OAEP'])

    token = jwt.JWT(header={'alg': 'RSA-OAEP', 'enc': 'A256GCM'},
                    claims={'secret': 1})
    token.make_encrypted_token(adapter.public_jwk())
    parsed = jwt.JWT(key=adapter, jwt=token.serialize())
    assert json_decode(parsed.claims) == {'secret': 1}


def test_rsa_oaep_jwe_unwrap_via_provider():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    provider = FakeProvider(key)
    enc_adapter = ExternalKeyAdapter(
        key.public(), unwrap_cb=provider.unwrap_cb,
        unwrapping_algs=['RSA-OAEP'])

    # Encrypt with the public key using the ordinary JWE path.
    encrypted = jwe.JWE(
        b'secret message',
        protected={'alg': 'RSA-OAEP', 'enc': 'A256GCM'})
    encrypted.add_recipient(enc_adapter.public_jwk())
    token = encrypted.serialize(compact=True)

    # Decrypt through the external unwrap callback.
    decrypted = jwe.JWE()
    decrypted.deserialize(token, enc_adapter)
    assert decrypted.payload == b'secret message'

    call = provider.calls[0]
    assert call['op'] == 'unwrap'
    assert call['alg'] == 'RSA-OAEP'
    assert isinstance(call['data'], bytes)
    assert call['headers']['alg'] == 'RSA-OAEP'


def test_provider_refusal_propagates_jws():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    provider = FakeProvider(key, refuse=True)
    adapter = ExternalKeyAdapter(
        key.public(), sign_cb=provider.sign_cb, signing_algs=['RS256'])

    token = jws.JWS(b'data')
    with pytest.raises(ExternalKeyProviderError):
        token.add_signature(adapter, alg='RS256')
    assert provider.calls[0]['op'] == 'sign'


def test_provider_refusal_propagates_jwe():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    provider = FakeProvider(key, refuse=True)
    adapter = ExternalKeyAdapter(
        key.public(), unwrap_cb=provider.unwrap_cb,
        unwrapping_algs=['RSA-OAEP'])

    encrypted = jwe.JWE(
        b'data', protected={'alg': 'RSA-OAEP', 'enc': 'A256GCM'})
    encrypted.add_recipient(adapter.public_jwk())
    token = encrypted.serialize(compact=True)

    decrypted = jwe.JWE()
    from jwcrypto.common import InvalidJWEData
    with pytest.raises(InvalidJWEData) as exc:
        decrypted.deserialize(token, adapter)
    assert 'ExternalKeyProviderError' in str(exc.value)
    # The direct callback path propagates the provider error unchanged.
    with pytest.raises(ExternalKeyProviderError):
        adapter.unwrap('RSA-OAEP', b'ek-bytes', 256,
                       {'alg': 'RSA-OAEP'})


def test_bad_signature_return_rejected():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    provider = FakeProvider(key, bad_signature=True)
    adapter = ExternalKeyAdapter(
        key.public(), sign_cb=provider.sign_cb, signing_algs=['RS256'])

    token = jws.JWS(b'data')
    with pytest.raises(InvalidExternalKeyResponse):
        token.add_signature(adapter, alg='RS256')


def test_non_bytes_signature_return_rejected():
    key = jwk.JWK.generate(kty='RSA', size=2048)

    def cb(alg, data, headers, adapter):
        return 'not bytes'

    adapter = ExternalKeyAdapter(
        key.public(), sign_cb=cb, signing_algs=['RS256'])
    with pytest.raises(InvalidExternalKeyResponse):
        adapter.sign('RS256', b'abc', {})


def test_bad_cek_length_rejected():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    adapter = ExternalKeyAdapter(
        key.public(),
        unwrap_cb=lambda alg, ek, headers, a: b'short',
        unwrapping_algs=['RSA-OAEP'])
    with pytest.raises(InvalidJWEKeyLength):
        adapter.unwrap('RSA-OAEP', b'ek-bytes', 256, {'alg': 'RSA-OAEP'})


def test_alg_not_in_allowed_set_rejected_before_callback():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    adapter, provider = _adapter(key, signing_algs=['RS256'])

    token = jws.JWS(b'data')
    # Header alg chosen outside the caller's allowed set.
    with pytest.raises(Exception):
        token.add_signature(adapter, alg='ES256')
    assert provider.calls == []

    with pytest.raises(InvalidExternalKeyOperation):
        adapter.sign('RS512', b'data', {})
    assert provider.calls == []


def test_unwrap_alg_not_allowed_rejected_before_callback():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    provider = FakeProvider(key)
    adapter = ExternalKeyAdapter(
        key.public(), unwrap_cb=provider.unwrap_cb,
        unwrapping_algs=['RSA-OAEP'])
    with pytest.raises(InvalidExternalKeyOperation):
        adapter.unwrap('RSA1_5', b'ek', 256, {})
    assert provider.calls == []


def test_encryption_use_key_rejected_for_signing():
    # An encryption-only key may not be signed with.
    key = jwk.JWK.generate(kty='RSA', size=2048, use='enc')
    adapter, provider = _adapter(key, signing_algs=['RS256'])

    token = jws.JWS(b'data')
    with pytest.raises(InvalidExternalKeyOperation):
        token.add_signature(adapter, alg='RS256')
    assert provider.calls == []


def test_key_ops_encrypt_rejected_for_signing():
    key = jwk.JWK.generate(kty='RSA', size=2048,
                           key_ops=['encrypt', 'wrapKey'])
    adapter, provider = _adapter(key, signing_algs=['RS256'])
    with pytest.raises(InvalidExternalKeyOperation):
        adapter.sign('RS256', b'data', {})
    assert provider.calls == []


def test_sign_use_key_rejected_for_unwrapping():
    key = jwk.JWK.generate(kty='RSA', size=2048, use='sig')
    provider = FakeProvider(key)
    adapter = ExternalKeyAdapter(
        key.public(), unwrap_cb=provider.unwrap_cb,
        unwrapping_algs=['RSA-OAEP'])
    with pytest.raises(InvalidExternalKeyOperation):
        adapter.unwrap('RSA-OAEP', b'ek', 256, {})
    assert provider.calls == []


def test_private_jwk_rejected():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key, sign_cb=lambda *a: b'',
                           signing_algs=['RS256'])


def test_symmetric_jwk_rejected():
    key = jwk.JWK.generate(kty='oct', size=256)
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key, sign_cb=lambda *a: b'',
                           signing_algs=['HS256'])


def test_unsupported_alg_rejected_at_construction():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    # HMAC cannot run on an asymmetric external key.
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key.public(),
                           sign_cb=lambda *a: b'',
                           signing_algs=['HS256'])
    # Wrong key type for the algorithm.
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key.public(),
                           sign_cb=lambda *a: b'',
                           signing_algs=['ES256'])
    # Unknown key management algorithm.
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key.public(),
                           unwrap_cb=lambda *a: b'',
                           unwrapping_algs=['A128KW'])


def test_algorithms_default_and_callback_validation():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    # A callback without an explicit list infers all key-compatible algs.
    adapter = ExternalKeyAdapter(key.public(), sign_cb=lambda *a: b'')
    assert 'RS256' in adapter.signing_algs
    assert 'ES256' not in adapter.signing_algs
    assert adapter.unwrapping_algs == []
    # Allowing algorithms without a callback is invalid.
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key.public(), signing_algs=['RS256'])
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key.public(), unwrapping_algs=['RSA-OAEP'])
    # An empty allow-list is invalid.
    with pytest.raises(InvalidExternalKeyConfig):
        ExternalKeyAdapter(key.public(), sign_cb=lambda *a: b'',
                           signing_algs=[])


def test_operation_without_callback_rejected():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    adapter = ExternalKeyAdapter(key.public())
    with pytest.raises(InvalidExternalKeyOperation):
        adapter.sign('RS256', b'data', {})
    with pytest.raises(InvalidExternalKeyOperation):
        adapter.unwrap('RSA-OAEP', b'ek', 256, {})
