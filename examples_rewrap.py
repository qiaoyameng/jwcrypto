#!/usr/bin/env python
"""End-to-end demonstration of explicit JWE re-wrapping.

The archived JWE gets an additional recipient without the payload being
re-encrypted: the original CEK is recovered and authenticated with an
existing recipient key, then wrapped for the new recipient using two
allowed key-wrap algorithms.
"""

from jwcrypto import jwe, jwk
from jwcrypto.common import json_decode, json_encode


def parts(token):
    """Return the byte-level authenticated envelope of a JWE."""
    d = json_decode(token)
    return {k: d[k] for k in ('protected', 'iv', 'ciphertext', 'tag', 'aad')
            if k in d}


def decrypt(token, key):
    obj = jwe.JWE()
    obj.deserialize(token, key)
    return obj.payload


def main():
    plaintext = b'quarterly-report-secret: revenue up 18%'
    aad = b'archive=2026Q3|channel=sealed-mail'

    # Original recipient: CEK wrapped with AES-128 Key Wrap
    old_key = jwk.JWK.generate(kty='oct', size=128, kid='alice')
    # Two new recipients, one per requested key-wrap algorithm
    new_kw_key = jwk.JWK.generate(kty='oct', size=256, kid='bob-a256kw')
    new_gcm_key = jwk.JWK.generate(kty='oct', size=128, kid='carol-a128gcmkw')

    token = jwe.JWE(plaintext=plaintext,
                    protected={'enc': 'A256GCM'},
                    aad=aad)
    token.add_recipient(old_key, header={'alg': 'A128KW', 'kid': 'alice'})
    original = token.serialize()
    original_parts = parts(original)

    print('== original envelope ==')
    for name, value in original_parts.items():
        print(f'  {name:11s} = {value}')

    # Re-wrap #1: A256KW
    r1 = jwe.JWE()
    r1.deserialize(original)
    r1.rewrap_recipient(old_key, new_kw_key,
                        header={'alg': 'A256KW', 'kid': 'bob-a256kw'})
    token1 = r1.serialize()

    # Re-wrap #2: A128GCMKW (on top of the already two-recipient token)
    r2 = jwe.JWE()
    r2.deserialize(token1)
    r2.rewrap_recipient(old_key, new_gcm_key,
                        header={'alg': 'A128GCMKW', 'kid': 'carol-a128gcmkw'})
    token2 = r2.serialize()

    final = json_decode(token2)
    print('\n== final token has', len(final['recipients']), 'recipients ==')
    for rec in final['recipients']:
        print(' ', json_encode(rec.get('header', {})))

    # 1) Every key recovers the SAME plaintext
    recovered = {
        'alice (A128KW)': decrypt(token2, old_key),
        'bob (A256KW)': decrypt(token2, new_kw_key),
        'carol (A128GCMKW)': decrypt(token2, new_gcm_key),
    }
    assert all(p == plaintext for p in recovered.values())
    print('\n== all three keys recover the same plaintext ==')
    for who, p in recovered.items():
        print(f'  {who:22s} -> {p!r}')

    # 2) Byte-for-byte comparison of the authenticated envelope
    final_parts = parts(token2)
    assert final_parts == original_parts, 'envelope changed!'
    print('\n== envelope byte comparison (original vs final) ==')
    for name in ('protected', 'aad', 'iv', 'ciphertext', 'tag'):
        same = final_parts.get(name) == original_parts.get(name)
        print(f'  {name:11s} identical: {same}')
    print('\nRESULT: CEK re-wrapped only; ciphertext/iv/tag/AAD untouched.')

    # 3) 'dir' must be refused (cannot carry an independently wrapped CEK)
    direct_cek = jwk.JWK.generate(kty='oct', size=256)
    dtoken = jwe.JWE(plaintext=b'direct-content',
                     protected={'alg': 'dir', 'enc': 'A256GCM'})
    dtoken.add_recipient(direct_cek)
    dser = dtoken.serialize(compact=True)
    dr = jwe.JWE()
    dr.deserialize(dser)
    try:
        dr.rewrap_recipient(direct_cek, new_kw_key,
                            header={'kid': 'would-be'})
    except (jwe.InvalidJWEOperation, jwe.InvalidJWEData) as exc:
        print(f"\n'dir' rejected: {exc}")

    # 4) Authentication failure must publish no new recipient
    attacker_key = jwk.JWK.generate(kty='oct', size=128)
    victim_new = jwk.JWK.generate(kty='oct', size=256)
    ar = jwe.JWE()
    ar.deserialize(original)
    before = len(json_decode(ar.serialize()).get(
        'recipients', [{}])) if 'recipients' in json_decode(ar.serialize()) \
        else 1
    try:
        ar.rewrap_recipient(attacker_key, victim_new,
                            header={'alg': 'A256KW', 'kid': 'intruder'})
    except jwe.InvalidJWEData as exc:
        after_obj = json_decode(ar.serialize())
        after = len(after_obj['recipients']) if 'recipients' in after_obj \
            else 1
        assert before == after == 1
        print(f'auth failure rejected ({type(exc).__name__}), '
              f'recipients still: {after}')


if __name__ == '__main__':
    main()
