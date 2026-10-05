# Copyright (C) 2026  JWCrypto Project Contributors - see LICENSE file

"""Nested JWT (sign-then-encrypt) support.

This module implements the "nested JWT" structure described in
RFC 7519 section 11.2, restricted to the only ordering accepted by
this API: an outer JWE carrying an inner JWS ("sign first, encrypt
afterwards").

Unlike :class:`jwcrypto.jwt.JWT`, the nested token is never parsed by
guessing its serialization. The expected structure is fixed and each
layer is processed in a strict, ordered sequence:

1. The outer token must be a JWE in compact serialization. It is
   decrypted only with the explicitly configured outer key source and
   after its algorithms and ``typ``/``cty`` headers have been checked.
2. The decrypted content must be a JWS in compact serialization. It is
   verified only with the explicitly configured inner key source, which
   never sees any data from the outer JWE header.
3. Only after the inner signature verifies are the claims exposed, and
   at that point issuer/audience/time validation is performed.

Any failure aborts the whole operation and no claims are exposed.
"""

from jwcrypto.common import JWException
from jwcrypto.common import base64url_decode
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwe import JWE
from jwcrypto.jwe import default_allowed_algs as _jwe_defaults
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jws import JWS
from jwcrypto.jws import default_allowed_algs as _jws_defaults
from jwcrypto.jwt import JWT


# Content-encryption ('enc') algorithms vs key-management ('alg')
# algorithms are distinct sets in JWA.
default_allowed_enc_algs = [
    'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
    'A128GCM', 'A192GCM', 'A256GCM']
"""Default allowed JWE content-encryption ('enc') algorithms."""

default_allowed_keymgmt_algs = [
    alg for alg in _jwe_defaults
    if alg not in default_allowed_enc_algs]
"""Default allowed JWE key-management ('alg') algorithms."""

default_allowed_sign_algs = list(_jws_defaults)
"""Default allowed JWS signing algorithms (the 'none' algorithm is
   never accepted for a nested JWT)."""

# 64KiB is plenty for a token carrying a claims document and keeps
# decompression/parser resource usage bounded.
default_max_inner_size = 64 * 1024
"""Default maximum accepted size (in bytes) of the decrypted inner
   token, including after decompression."""

default_max_token_size = 64 * 1024
"""Default maximum accepted size (in bytes) of the raw outer token."""


class ANY:
    """Policy marker: the header may be present or absent and its
    value is not checked."""


class InvalidNestedJWT(JWException):
    """The token is not a structurally valid sign-then-encrypt nested
    JWT according to the configured policy."""

    def __init__(self, message=None, exception=None):
        msg = 'Invalid nested JWT'
        if message:
            msg += ': %s' % message
        if exception:
            msg += ' {%s}' % str(exception)
        super(InvalidNestedJWT, self).__init__(msg)


def _norm_media_type(value):
    # Same normalization as JWT.norm_typ: a bare subtype gets the
    # 'application/' prefix.
    lc = value.lower()
    if '/' in lc:
        return lc
    return 'application/' + lc


class NestedJWTLayer:
    """Verification policy for one layer of a nested JWT.

    :param key: A :class:`jwcrypto.jwk.JWK` or
     :class:`jwcrypto.jwk.JWKSet`, or a callable taking no arguments
     that returns one. The callable is invoked while verifying the
     token, so key material can be fetched lazily. Required for
     verification.
    :param algs: Allowed key-management (outer JWE) or signing
     (inner JWS) algorithms.
    :param enc_algs: Allowed content-encryption algorithms; only valid
     for the outer JWE layer.
    :param typ: Expected ``typ`` header value (normalized per
     :rfc:`7519`). ``None`` requires the header to be absent, an
     :class:`ANY` value skips the check, a string must match.
    :param cty: Expected ``cty`` header value. Same semantics as
     ``typ``.
    """

    def __init__(self, key=None, algs=None, enc_algs=None,
                 typ=ANY, cty=ANY):
        self.key = key
        self.algs = algs
        self.enc_algs = enc_algs
        self.typ = typ
        self.cty = cty
        self._validate()

    def _validate(self):
        if not (self.key is None or
                isinstance(self.key, (JWK, JWKSet)) or
                callable(self.key)):
            raise ValueError(
                "key must be a JWK, JWKSet, callable or None")
        self._check_alg_list('algs', self.algs)
        self._check_alg_list('enc_algs', self.enc_algs)
        self._check_policy('typ', self.typ)
        self._check_policy('cty', self.cty)

    @staticmethod
    def _check_alg_list(name, value):
        if value is None:
            return
        if not isinstance(value, list) or not value or \
                any(not isinstance(a, str) for a in value):
            raise ValueError("%s must be a non-empty list of strings"
                             % name)

    @staticmethod
    def _check_policy(name, value):
        if value is not None and value is not ANY and \
                not isinstance(value, str):
            raise ValueError(
                "%s must be a string, None or nested_jwt.ANY" % name)


class NestedJWTConfig:
    """Configuration for verifying/creating a nested JWT.

    The outer layer is always a JWE and the inner layer is always a
    JWS. Each layer carries its own key source, allowed algorithms and
    ``typ``/``cty`` policy.

    By default the outer JWE is required to carry ``cty: "JWT"`` (the
    content type mandated for nested JWTs) and the inner JWS is
    required not to carry a ``cty`` header (which would indicate further
    nesting).

    :param outer: The outer JWE policy, as a :class:`NestedJWTLayer`
     or the ``key`` argument; remaining outer parameters are taken
     from ``outer_algs``/``outer_enc_algs``/``outer_typ``/``outer_cty``.
    :param inner: The inner JWS policy, as a :class:`NestedJWTLayer`
     or the ``key`` argument; remaining inner parameters are taken
     from ``inner_algs``/``inner_typ``/``inner_cty``.
    :param max_token_size: Maximum accepted size, in bytes, of the
     raw outer token.
    :param max_inner_size: Maximum accepted size, in bytes, of the
     decrypted inner token (this also bounds decompressed output).
    :param leeway: Clock skew allowance in seconds for the ``exp`` and
     ``nbf`` claims.
    """

    def __init__(self, outer=None, inner=None,
                 outer_algs=None, outer_enc_algs=None,
                 outer_typ=ANY, outer_cty='JWT',
                 inner_algs=None, inner_typ=ANY, inner_cty=None,
                 max_token_size=default_max_token_size,
                 max_inner_size=default_max_inner_size,
                 leeway=60):
        if isinstance(outer, NestedJWTLayer):
            if outer_algs is not None or outer_enc_algs is not None or \
                    outer_typ is not ANY or outer_cty != 'JWT':
                raise ValueError("outer layer and outer_* parameters "
                                 "are mutually exclusive")
            self.outer = outer
        else:
            self.outer = NestedJWTLayer(
                key=outer, algs=outer_algs, enc_algs=outer_enc_algs,
                typ=outer_typ, cty=outer_cty)

        if isinstance(inner, NestedJWTLayer):
            if inner_algs is not None or inner_typ is not ANY or \
                    inner_cty is not None:
                raise ValueError("inner layer and inner_* parameters "
                                 "are mutually exclusive")
            self.inner = inner
        else:
            self.inner = NestedJWTLayer(
                key=inner, algs=inner_algs,
                typ=inner_typ, cty=inner_cty)

        self._check_layers()

        if not isinstance(max_token_size, int) or max_token_size <= 0:
            raise ValueError("max_token_size must be a positive integer")
        if not isinstance(max_inner_size, int) or max_inner_size <= 0:
            raise ValueError("max_inner_size must be a positive integer")
        if not isinstance(leeway, int) or leeway < 0:
            raise ValueError("leeway must be a non-negative integer")

        self.max_token_size = max_token_size
        self.max_inner_size = max_inner_size
        self.leeway = leeway

    def _check_layers(self):
        # Apply library defaults when no explicit algorithm policy is
        # given (explicit empty lists are rejected in NestedJWTLayer).
        if self.outer.algs is None:
            self.outer.algs = list(default_allowed_keymgmt_algs)
        if self.outer.enc_algs is None:
            self.outer.enc_algs = list(default_allowed_enc_algs)
        if self.inner.algs is None:
            self.inner.algs = list(default_allowed_sign_algs)
        if self.inner.enc_algs is not None:
            raise ValueError("enc_algs is valid only on the outer JWE "
                             "layer")
        # The 'none' algorithm must never be accepted for the inner
        # signature.
        if self.inner.algs is not None and \
                'none' in self.inner.algs:
            raise ValueError("'none' is not an allowed inner JWS "
                             "algorithm")


class NestedJWT:
    """A sign-then-encrypt nested JWT.

    Deserialization performs, in order:

    1. structural validation of the compact JWE outer token,
    2. outer header policy checks (algorithms and ``typ``/``cty``),
    3. outer decryption using only the configured outer key source,
    4. structural validation of the compact JWS inner token and its
       header policy checks,
    5. inner signature verification using only the configured inner
       key source,
    6. JSON parsing of the claims and issuer/audience/time checks.

    The verified claims are available only after all steps succeed.

    :param token: The raw nested JWT (compact serialization).
    :param config: A :class:`NestedJWTConfig` describing both layers.
    :param check_claims: An optional dict of claims that must be present
     in the token, following the same semantics as
     :class:`jwcrypto.jwt.JWT`. ``False`` disables claim checks. If
     omitted the ``exp``/``nbf`` claims are still validated when
     present.
    """

    def __init__(self, token=None, config=None, check_claims=None,
                 leeway=None):
        if config is None:
            raise ValueError("A NestedJWTConfig is required")
        if not isinstance(config, NestedJWTConfig):
            raise TypeError("config must be a NestedJWTConfig")

        self._config = config
        self._check_claims = check_claims
        if leeway is not None:
            if not isinstance(leeway, int) or leeway < 0:
                raise ValueError("leeway must be a non-negative integer")
            self._leeway = leeway
        else:
            self._leeway = config.leeway

        self._jwe = None
        self._jws = None
        self._outer_header = None
        self._inner_header = None
        self._claims = None

        if token is not None:
            self.deserialize(token)

    # -- public, post-verification state ---------------------------------

    @property
    def config(self):
        return self._config

    @property
    def outer_header(self):
        """The outer JWE protected header, available only after the
        whole nested token has been fully verified."""
        if self._outer_header is None:
            raise KeyError("outer header not available")
        return self._outer_header

    @property
    def inner_header(self):
        """The inner JWS header, available only after the whole nested
        token has been fully verified."""
        if self._inner_header is None:
            raise KeyError("inner header not available")
        return self._inner_header

    @property
    def claims(self):
        """The verified claims as a raw JSON string."""
        if self._claims is None:
            raise KeyError("claims not available")
        return self._claims

    @property
    def claims_dict(self):
        """The verified claims as a dict."""
        return json_decode(self.claims)

    # -- helpers ----------------------------------------------------------

    def _key(self, layer):
        key = layer.key
        if callable(key):
            key = key()
        if not isinstance(key, (JWK, JWKSet)):
            raise InvalidNestedJWT(
                "key source did not provide a JWK/JWKSet")
        return key

    @staticmethod
    def _decode_protected(segment, what):
        # Only a dict protected header is valid. This runs before any
        # cryptographic operation so that policy (algorithms/typ/cty)
        # is enforced on authenticated-but-not-yet-trusted input.
        try:
            raw = base64url_decode(segment)
            header = json_decode(raw)
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidNestedJWT(
                "malformed %s protected header" % what) from e
        if not isinstance(header, dict):
            raise InvalidNestedJWT(
                "%s protected header is not a JSON object" % what)
        return header

    @staticmethod
    def _check_header_policy(header, layer, what):
        for name in ('typ', 'cty'):
            policy = getattr(layer, name)
            if policy is ANY:
                continue
            value = header.get(name)
            if policy is None:
                if value is not None:
                    raise InvalidNestedJWT(
                        "%s header '%s' must not be present" % (what, name))
            elif not isinstance(value, str) or \
                    _norm_media_type(value) != _norm_media_type(policy):
                raise InvalidNestedJWT(
                    "unexpected %s '%s' header: %r" % (what, name, value))

    @staticmethod
    def _check_algorithms(header, layer, what):
        alg = header.get('alg')
        if not isinstance(alg, str):
            raise InvalidNestedJWT("%s 'alg' header missing" % what)
        if alg not in layer.algs:
            raise InvalidNestedJWT(
                "%s algorithm %r is not allowed" % (what, alg))
        if what == 'outer JWE':
            enc = header.get('enc')
            if not isinstance(enc, str):
                raise InvalidNestedJWT("outer JWE 'enc' header missing")
            if enc not in layer.enc_algs:
                raise InvalidNestedJWT(
                    "outer JWE content-encryption algorithm %r is not "
                    "allowed" % enc)
        elif alg == 'none':
            # Defense in depth: even an explicit opt-in is rejected.
            raise InvalidNestedJWT(
                "inner JWS must be signed ('none' is not accepted)")

    @staticmethod
    def _compact_parts(token, expected, what):
        # Explicitly reject JSON Serialization; compact JWS/JWE only.
        if not isinstance(token, str):
            raise InvalidNestedJWT("%s must be a compact string" % what)
        stripped = token.strip()
        if stripped[:1] in ('{', '['):
            raise InvalidNestedJWT(
                "only compact serialization is accepted for %s" % what)
        if stripped != token:
            raise InvalidNestedJWT(
                "%s must not contain leading/trailing whitespace" % what)
        parts = token.split('.')
        if len(parts) != expected:
            raise InvalidNestedJWT(
                "expected a %d-part compact %s, got %d parts" % (
                    expected, what, len(parts)))
        return parts

    @staticmethod
    def _valid_b64u(segment):
        if not segment:
            return False
        try:
            base64url_decode(segment)
        except Exception:  # pylint: disable=broad-except
            return False
        return True

    # -- verification -----------------------------------------------------

    def deserialize(self, token):
        """Verify a raw nested JWT.

        The outer JWE is authenticated and decrypted first; the inner
        JWS is parsed and verified only afterwards, using the separate
        inner key source. Claims are stored on this object only after
        every check succeeds.

        :param token: The raw nested JWT in compact serialization.
        :raises InvalidNestedJWT: if the token does not match the
         configured structure/policy.
        :raises jwcrypto.common.InvalidJWEData: if decryption fails.
        :raises jwcrypto.jws.InvalidJWSSignature: if the inner
         signature does not verify.
        :raises jwcrypto.jwt.JWTExpired/JWTNotYetValid/...: if the
         claims do not satisfy the requested checks.
        """
        # Reset all state: a failed re-verification must never leave
        # previously verified data exposed.
        self._jwe = None
        self._jws = None
        self._outer_header = None
        self._inner_header = None
        self._claims = None

        cfg = self._config

        # 1. The outer token must be a 5-part compact JWE.
        if len(token) > cfg.max_token_size:
            raise InvalidNestedJWT(
                "raw token exceeds maximum allowed size (%d)" %
                cfg.max_token_size)
        op, ek, iv, ct, tag = self._compact_parts(token, 5, "outer JWE")
        for segment in (op, iv, ct, tag):
            if not self._valid_b64u(segment):
                raise InvalidNestedJWT("malformed outer JWE segment")
        # The encrypted key segment is allowed to be empty ('dir',
        # ECDH-ES, ...).
        if ek and not self._valid_b64u(ek):
            raise InvalidNestedJWT("malformed outer JWE encrypted key")

        # 2. Enforce outer policy from the (authenticated post-decrypt,
        #    but attacker-controlled pre-trust) protected header.
        outer_header = self._decode_protected(op, "outer JWE")
        self._check_algorithms(outer_header, cfg.outer, 'outer JWE')
        self._check_header_policy(outer_header, cfg.outer, 'outer JWE')

        # 3. Decrypt only with the configured outer key source.
        outer_key = self._key(cfg.outer)
        jwe = JWE()
        jwe.allowed_algs = cfg.outer.algs + cfg.outer.enc_algs
        jwe.deserialize(token, None)
        jwe.decrypt(outer_key, max_plaintext=cfg.max_inner_size)

        try:
            inner_raw = jwe.plaintext.decode('utf-8')
        except UnicodeDecodeError as e:
            raise InvalidNestedJWT(
                "decrypted inner token is not valid UTF-8") from e
        if len(inner_raw) > cfg.max_inner_size:
            raise InvalidNestedJWT(
                "decrypted inner token exceeds maximum allowed size "
                "(%d)" % cfg.max_inner_size)

        # 4. The decrypted content must be a 3-part compact JWS. A JWE
        #    inside a JWE, a JSON Serialization or plain JSON are all
        #    rejected here; no format probing is attempted.
        hp, pp, sp = self._compact_parts(inner_raw, 3, "inner JWS")
        for segment in (hp, pp):
            if not self._valid_b64u(segment):
                raise InvalidNestedJWT("malformed inner JWS segment")
        # An empty signature segment is structurally legal for an
        # unsigned JWS; let it through so the algorithm/signature check
        # below rejects it (the 'none' algorithm and an empty signature
        # are never accepted).
        if sp and not self._valid_b64u(sp):
            raise InvalidNestedJWT("malformed inner JWS segment")

        inner_header = self._decode_protected(hp, "inner JWS")
        if inner_header.get('b64') is False:
            raise InvalidNestedJWT(
                "inner JWS cannot use an unencoded (b64=false) payload")
        self._check_algorithms(inner_header, cfg.inner, 'inner JWS')
        self._check_header_policy(inner_header, cfg.inner, 'inner JWS')

        # 5. Verify the signature only with the inner key source. The
        #    outer JWE header is never consulted here.
        inner_key = self._key(cfg.inner)
        jws = JWS()
        jws.allowed_algs = cfg.inner.algs
        jws.deserialize(inner_raw, None)
        jws.verify(inner_key)

        # 6. Only now expose and validate the payload/claims.
        try:
            payload = jws.payload
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8')
            claims_obj = json_decode(payload)
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidNestedJWT(
                "inner JWS payload is not valid JSON") from e
        if not isinstance(claims_obj, dict):
            # A nested JWS/JWE compact string is not JSON and was
            # rejected above; a JSON object is the only valid claims
            # document, so nesting ends at two layers.
            raise InvalidNestedJWT(
                "inner JWS payload must be a JSON claims object")

        self._check_claims_document(payload)

        # All checks passed: commit the verified state atomically.
        self._jwe = jwe
        self._jws = jws
        self._outer_header = outer_header
        self._inner_header = inner_header
        self._claims = payload

    def _check_claims_document(self, payload):
        # Reuse JWT's RFC 7519 claim checks (iss/aud/exp/nbf/...)
        # without invoking any JWS/JWE parsing logic.
        checker = JWT(check_claims=self._check_claims)
        checker.leeway = self._leeway
        # pylint: disable=protected-access
        checker._claims = payload
        checker._check_provided_claims()
        # pylint: enable=protected-access

    # -- creation ---------------------------------------------------------

    @classmethod
    def sign_and_encrypt(cls, claims, signing_key, encryption_key,
                         config=None, sign_alg=None, enc_alg=None,
                         enc_enc=None, inner_headers=None,
                         outer_headers=None):
        """Build a sign-then-encrypt nested JWT.

        Convenience constructor that signs ``claims`` with
        ``signing_key`` and encrypts the resulting compact JWS with
        ``encryption_key``.

        :param claims: A dict (JSON-encoded) or a JSON string.
        :param signing_key: The inner JWS signing :class:`jwcrypto.jwk.JWK`.
        :param encryption_key: The outer JWE :class:`jwcrypto.jwk.JWK`.
        :param config: Optional :class:`NestedJWTConfig` used to pick
         default algorithms and the outer ``cty`` header.
        :param sign_alg: Override the inner signing algorithm.
        :param enc_alg: Override the outer key-management algorithm.
        :param enc_enc: Override the outer content-encryption algorithm.
        :param inner_headers: Optional extra inner JWS protected headers.
        :param outer_headers: Optional extra outer JWE protected headers.
        :return: The compact-serialized nested JWT.
        :rtype: str
        """
        if config is None:
            config = NestedJWTConfig(
                outer=encryption_key, inner=signing_key)

        if isinstance(claims, dict):
            claims = json_encode(claims)

        if sign_alg is None:
            sign_alg = cls._default_sign_alg(
                signing_key, config.inner.algs)
        if enc_alg is None:
            enc_alg = cls._default_keymgmt_alg(
                encryption_key, config.outer.algs)
        if enc_enc is None:
            enc_enc = config.outer.enc_algs[0]

        iprotected = {}
        if inner_headers:
            iprotected.update(inner_headers)
        iprotected['alg'] = sign_alg

        jws = JWS(claims)
        jws.add_signature(signing_key, protected=json_encode(iprotected))
        inner_token = jws.serialize(compact=True)

        oprotected = {}
        if outer_headers:
            oprotected.update(outer_headers)
        oprotected['alg'] = enc_alg
        oprotected['enc'] = enc_enc
        # Mark the encrypted content as a JWT unless the caller set an
        # explicit cty policy in the outer headers.
        if config.outer.cty is not ANY and \
                config.outer.cty is not None and 'cty' not in oprotected:
            oprotected['cty'] = config.outer.cty

        jwe = JWE(inner_token, json_encode(oprotected))
        jwe.add_recipient(encryption_key)
        return jwe.serialize(compact=True)

    @staticmethod
    def _default_sign_alg(key, allowed):
        kty = key.get('kty')
        candidates = {
            'oct': ['HS256', 'HS384', 'HS512'],
            'RSA': ['PS256', 'RS256'],
            'EC': ['ES256', 'ES384', 'ES512', 'ES256K'],
            'OKP': ['EdDSA', 'Ed25519', 'Ed448'],
        }.get(kty, [])
        for alg in candidates:
            if alg in allowed:
                return alg
        return allowed[0]

    @staticmethod
    def _default_keymgmt_alg(key, allowed):
        kty = key.get('kty')
        if kty == 'oct':
            candidates = ['dir', 'A256KW', 'A192KW', 'A128KW',
                          'A256GCMKW', 'A192GCMKW', 'A128GCMKW']
        elif kty == 'RSA':
            candidates = ['RSA-OAEP-256', 'RSA-OAEP']
        elif kty == 'EC':
            candidates = ['ECDH-ES+A256KW', 'ECDH-ES+A192KW',
                          'ECDH-ES+A128KW', 'ECDH-ES']
        elif kty == 'OKP':
            candidates = ['ECDH-ES+A256KW', 'ECDH-ES+A192KW',
                          'ECDH-ES+A128KW', 'ECDH-ES']
        else:
            candidates = []
        for alg in candidates:
            if alg in allowed:
                return alg
        return allowed[0]
