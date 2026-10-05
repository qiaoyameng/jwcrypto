# Copyright (C) 2015  JWCrypto Project Contributors - see LICENSE file

import copy
import time
import uuid

from typing_extensions import deprecated

from jwcrypto.common import JWException, JWKeyNotFound
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jwe import JWE, InvalidJWEData
from jwcrypto.jwe import default_allowed_algs as jwe_algs
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jws import JWS
from jwcrypto.jws import default_allowed_algs as jws_algs


# RFC 7519 - 4.1
# name: description
JWTClaimsRegistry = {'iss': 'Issuer',
                     'sub': 'Subject',
                     'aud': 'Audience',
                     'exp': 'Expiration Time',
                     'nbf': 'Not Before',
                     'iat': 'Issued At',
                     'jti': 'JWT ID'}
"""Registry of RFC 7519 defined claims"""


# do not use this unless you know about CVE-2022-3102
JWT_expect_type = True
"""This module parameter can disable the use of the expectation
   feature that has been introduced to fix CVE-2022-3102. This knob
   has been added as a workaround for applications that can't be
   immediately refactored to deal with the change in behavior but it
   is considered deprecated and will be removed in a future release.
"""

# Limit the size of the plaintext we accept from the outer JWE of a
# nested JWT by default. This bounds both the inner token size and,
# when compression is used, the total decompressed size.
default_max_nested_payload_size = 256 * 1024


class JWTExpired(JWException):
    """JSON Web Token is expired.

    This exception is raised when a token is expired according to its claims.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Token expired'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTExpired, self).__init__(msg)


class JWTNotYetValid(JWException):
    """JSON Web Token is not yet valid.

    This exception is raised when a token is not valid yet according to its
    claims.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Token not yet valid'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTNotYetValid, self).__init__(msg)


class JWTMissingClaim(JWException):
    """JSON Web Token claim is invalid.

    This exception is raised when a claim does not match the expected value.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid Claim Value'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTMissingClaim, self).__init__(msg)


class JWTInvalidClaimValue(JWException):
    """JSON Web Token claim is invalid.

    This exception is raised when a claim does not match the expected value.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid Claim Value'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTInvalidClaimValue, self).__init__(msg)


class JWTInvalidClaimFormat(JWException):
    """JSON Web Token claim format is invalid.

    This exception is raised when a claim is not in a valid format.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid Claim Format'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTInvalidClaimFormat, self).__init__(msg)


@deprecated('')
class JWTMissingKeyID(JWException):
    """JSON Web Token is missing key id.

    This exception is raised when trying to decode a JWT with a key set
    that does not have a kid value in its header.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Missing Key ID'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTMissingKeyID, self).__init__(msg)


class JWTMissingKey(JWKeyNotFound):
    """JSON Web Token is using a key not in the key set.

    This exception is raised if the key that was used is not available
    in the passed key set.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Missing Key'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTMissingKey, self).__init__(msg)


class JWTInvalidHeaderParameter(JWException):
    """JSON Web Token header parameter is missing or invalid.

    This exception is raised when a JOSE header parameter does not
    match the expected value, for example when the 'cty' or 'typ'
    policy of a nested JWT is not satisfied.
    """

    def __init__(self, message=None, exception=None):
        msg = None
        if message:
            msg = str(message)
        else:
            msg = 'Invalid Header Parameter'
        if exception:
            msg += ' {%s}' % str(exception)
        super(JWTInvalidHeaderParameter, self).__init__(msg)


class JWT:
    """JSON Web token object

    This object represent a generic token.
    """

    def __init__(self, header=None, claims=None, jwt=None, key=None,
                 algs=None, default_claims=None, check_claims=None,
                 expected_type=None, strict_serialization=False):
        """Creates a JWT object.

        :param header: A dict or a JSON string with the JWT Header data.
        :param claims: A dict or a string with the JWT Claims data.
        :param jwt: a 'raw' JWT token
        :param key: A (:class:`jwcrypto.jwk.JWK`) key to deserialize
         the token. A (:class:`jwcrypto.jwk.JWKSet`) can also be used.
        :param algs: An optional list of allowed algorithms
        :param default_claims: An optional dict with default values for
         registered claims. A None value for NumericDate type claims
         will cause generation according to system time. Only the values
         from RFC 7519 - 4.1 are evaluated.
        :param check_claims: An optional dict of claims that must be
         present in the token, if the value is not None the claim must
         match exactly.
        :param expected_type: An optional string that defines what kind
         of token to expect when validating a deserialized token.
         Supported values: "JWS" or "JWE"
         If left to None the code will try to detect what the expected
         type is based on other parameters like 'algs' and will default
         to JWS if no hints are found. It has no effect on token creation.
        :param strict_serialization: An optional boolean (default False).
         RFC 7519 mandates that a JWT uses the JWS/JWE Compact
         Serialization. When set to True any token presented in the
         JWS/JWE JSON Serialization is rejected at deserialization time,
         so only the compact representation is accepted. The default is
         False to preserve backwards compatibility. It has no effect on
         token creation, which always produces the compact serialization.

        Note: either the header,claims or jwt,key parameters should be
        provided as a deserialization operation (which occurs if the jwt
        is provided) will wipe any header or claim provided by setting
        those obtained from the deserialization of the jwt token.

        Note: if check_claims is not provided the 'exp' and 'nbf' claims
        are checked if they are set on the token but not enforced if not
        set. Any other RFC 7519 registered claims are checked only for
        format conformance.
        """

        self._header = None
        self._claims = None
        self._token = None
        self._algs = algs
        self._reg_claims = None
        self._check_claims = None
        self._leeway = 60  # 1 minute clock skew allowed
        self._validity = 600  # 10 minutes validity (up to 11 with leeway)
        self.deserializelog = None
        self._expected_type = expected_type
        self._strict_serialization = strict_serialization

        if header:
            self.header = header

        if default_claims is not None:
            self._reg_claims = default_claims

        if check_claims is not None:
            if check_claims is not False:
                self._check_check_claims(check_claims)
            self._check_claims = check_claims

        if claims is not None:
            self.claims = claims

        if jwt is not None:
            self.deserialize(jwt, key)

    @property
    def header(self):
        if self._header is None:
            raise KeyError("'header' not set")
        return self._header

    @header.setter
    def header(self, h):
        if isinstance(h, dict):
            eh = json_encode(h)
        else:
            eh = h
            h = json_decode(eh)

        if h.get('b64') is False:
            raise ValueError("b64 header is invalid."
                             "JWTs cannot use unencoded payloads")
        self._header = eh

    @property
    def claims(self):
        if self._claims is None:
            raise KeyError("'claims' not set")
        return self._claims

    @claims.setter
    def claims(self, data):
        if not isinstance(data, dict):
            if not self._reg_claims:
                # no default_claims, can return immediately
                self._claims = data
                return
            data = json_decode(data)
        else:
            # _add_default_claims modifies its argument
            # so we must always copy it.
            data = copy.deepcopy(data)

        self._add_default_claims(data)
        self._claims = json_encode(data)

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, t):
        if isinstance(t, JWS) or isinstance(t, JWE) or isinstance(t, JWT):
            self._token = t
        else:
            raise TypeError("Invalid token type, must be one of JWS,JWE,JWT")

    @property
    def leeway(self):
        return self._leeway

    @leeway.setter
    def leeway(self, lwy):
        self._leeway = int(lwy)

    @property
    def validity(self):
        return self._validity

    @validity.setter
    def validity(self, v):
        self._validity = int(v)

    def _expected_type_heuristics(self, key=None):
        if self._expected_type is None and self._algs:
            if set(self._algs).issubset(jwe_algs + ['RSA1_5']):
                self._expected_type = "JWE"
            elif set(self._algs).issubset(jws_algs):
                self._expected_type = "JWS"
        if self._expected_type is None and self._header:
            if "enc" in json_decode(self._header):
                self._expected_type = "JWE"
        if self._expected_type is None and key is not None:
            if isinstance(key, JWK):
                use = key.get('use')
                if use == 'sig':
                    self._expected_type = "JWS"
                elif use == 'enc':
                    self._expected_type = "JWE"
            elif isinstance(key, JWKSet):
                all_use = None
                # we can infer only if all keys are of the same type
                for k in key:
                    use = k.get('use')
                    if all_use is None:
                        all_use = use
                    elif use != all_use:
                        all_use = None
                        break
                if all_use == 'sig':
                    self._expected_type = "JWS"
                elif all_use == 'enc':
                    self._expected_type = "JWE"
        if self._expected_type is None and key is not None:
            if isinstance(key, JWK):
                ops = key.get('key_ops')
                if ops:
                    if not isinstance(ops, list):
                        ops = [ops]
                    if set(ops).issubset(['sign', 'verify']):
                        self._expected_type = "JWS"
                    elif set(ops).issubset(['encrypt', 'decrypt']):
                        self._expected_type = "JWE"
            elif isinstance(key, JWKSet):
                all_ops = None
                ttype = None
                # we can infer only if all keys are of the same type
                for k in key:
                    ops = k.get('key_ops')
                    if ops:
                        if not isinstance(ops, list):
                            ops = [ops]
                        if all_ops is None:
                            if set(ops).issubset(['sign', 'verify']):
                                all_ops = set(['sign', 'verify'])
                                ttype = "JWS"
                            elif set(ops).issubset(['encrypt', 'decrypt']):
                                all_ops = set(['encrypt', 'decrypt'])
                                ttype = "JWE"
                            else:
                                ttype = None
                                break
                        else:
                            if not set(ops).issubset(all_ops):
                                ttype = None
                                break
                    elif all_ops:
                        ttype = None
                        break
                if ttype:
                    self._expected_type = ttype
        if self._expected_type is None:
            self._expected_type = "JWS"
        return self._expected_type

    @property
    def expected_type(self):
        if self._expected_type is not None:
            return self._expected_type

        # If no expected type is set we default to accept only JWSs,
        # however to improve backwards compatibility we try some
        # heuristic to see if there has been strong indication of
        # what the expected token type is.
        return self._expected_type_heuristics()

    @expected_type.setter
    def expected_type(self, v):
        if v in ["JWS", "JWE"]:
            self._expected_type = v
        else:
            raise ValueError("Invalid value, must be 'JWS' or 'JWE'")

    def _add_optional_claim(self, name, claims):
        if name in claims:
            return
        val = self._reg_claims.get(name, None)
        if val is not None:
            claims[name] = val

    def _add_time_claim(self, name, claims, defval):
        if name in claims:
            return
        if name in self._reg_claims:
            if self._reg_claims[name] is None:
                claims[name] = defval
            else:
                claims[name] = self._reg_claims[name]

    def _add_jti_claim(self, claims):
        if 'jti' in claims or 'jti' not in self._reg_claims:
            return
        claims['jti'] = str(uuid.uuid4())

    def _add_default_claims(self, claims):
        if self._reg_claims is None:
            return

        now = int(time.time())
        self._add_optional_claim('iss', claims)
        self._add_optional_claim('sub', claims)
        self._add_optional_claim('aud', claims)
        self._add_time_claim('exp', claims, now + self.validity)
        self._add_time_claim('nbf', claims, now)
        self._add_time_claim('iat', claims, now)
        self._add_jti_claim(claims)

    def _check_string_claim(self, name, claims):
        if name not in claims or claims[name] is None:
            return
        if not isinstance(claims[name], str):
            raise JWTInvalidClaimFormat(
                "Claim %s is not a StringOrURI type" % (name, ))

    def _check_array_or_string_claim(self, name, claims):
        if name not in claims or claims[name] is None:
            return
        if isinstance(claims[name], list):
            if any(not isinstance(claim, str) for claim in claims[name]):
                raise JWTInvalidClaimFormat(
                    "Claim %s contains non StringOrURI types" % (name, ))
        elif not isinstance(claims[name], str):
            raise JWTInvalidClaimFormat(
                "Claim %s is not a StringOrURI type" % (name, ))

    def _check_integer_claim(self, name, claims):
        if name not in claims or claims[name] is None:
            return
        try:
            int(claims[name])
        except ValueError as e:
            raise JWTInvalidClaimFormat(
                "Claim %s is not an integer" % (name, )) from e

    def _check_exp(self, claim, limit, leeway):
        if claim < limit - leeway:
            raise JWTExpired('Expired at %d, time: %d(leeway: %d)' % (
                             claim, limit, leeway))

    def _check_nbf(self, claim, limit, leeway):
        if claim > limit + leeway:
            raise JWTNotYetValid('Valid from %d, time: %d(leeway: %d)' % (
                                 claim, limit, leeway))

    def _check_default_claims(self, claims):
        self._check_string_claim('iss', claims)
        self._check_string_claim('sub', claims)
        self._check_array_or_string_claim('aud', claims)
        self._check_integer_claim('exp', claims)
        self._check_integer_claim('nbf', claims)
        self._check_integer_claim('iat', claims)
        self._check_string_claim('jti', claims)
        self._check_string_claim('typ', claims)

        if self._check_claims is None:
            if 'exp' in claims:
                self._check_exp(claims['exp'], time.time(), self._leeway)
            if 'nbf' in claims:
                self._check_nbf(claims['nbf'], time.time(), self._leeway)

    def _check_check_claims(self, check_claims):
        self._check_string_claim('iss', check_claims)
        self._check_string_claim('sub', check_claims)
        self._check_array_or_string_claim('aud', check_claims)
        self._check_string_claim('scope', check_claims)
        self._check_integer_claim('exp', check_claims)
        self._check_integer_claim('nbf', check_claims)
        self._check_integer_claim('iat', check_claims)
        self._check_string_claim('jti', check_claims)
        self._check_string_claim('typ', check_claims)

    def _check_provided_claims(self):
        # check_claims can be set to False to skip any check
        if self._check_claims is False:
            return

        try:
            claims = json_decode(self.claims)
            if not isinstance(claims, dict):
                raise ValueError()
        except ValueError as e:
            if self._check_claims is not None:
                raise JWTInvalidClaimFormat("Claims check requested "
                                            "but claims is not a json "
                                            "dict") from e
            return

        self._check_default_claims(claims)

        if self._check_claims is None:
            return

        for name, value in self._check_claims.items():
            if name not in claims:
                raise JWTMissingClaim("Claim %s is missing" % (name, ))

            if name in ['iss', 'sub', 'jti']:
                if value is not None and value != claims[name]:
                    raise JWTInvalidClaimValue(
                        "Invalid '%s' value. Expected '%s' got '%s'" % (
                            name, value, claims[name]))

            elif name == 'aud':
                if value is not None:
                    if isinstance(claims[name], list):
                        tclaims = claims[name]
                    else:
                        tclaims = [claims[name]]
                    if isinstance(value, list):
                        cclaims = value
                    else:
                        cclaims = [value]
                    token_audiences = set(tclaims)
                    if not any(v in token_audiences for v in cclaims):
                        raise JWTInvalidClaimValue(
                            "Invalid '{}' value. Expected '{}' in '{}'".format(
                                name, claims[name], value))

            elif name == 'exp':
                if value is not None:
                    self._check_exp(claims[name], value, 0)
                else:
                    self._check_exp(claims[name], time.time(), self._leeway)

            elif name == 'nbf':
                if value is not None:
                    self._check_nbf(claims[name], value, 0)
                else:
                    self._check_nbf(claims[name], time.time(), self._leeway)

            elif name == 'typ':
                if value is not None:
                    if self.norm_typ(value) != self.norm_typ(claims[name]):
                        raise JWTInvalidClaimValue("Invalid '%s' value. '%s'"
                                                   " does not normalize to "
                                                   "'%s'" % (name,
                                                             claims[name],
                                                             value))
            elif name == 'scope':
                if value is not None:
                    if not isinstance(claims[name], str):
                        raise JWTInvalidClaimValue(
                            "Invalid '%s' value. Scope list has to be "
                            "a string, got a %s instead: %s" % (
                                name, type(claims[name]), str(claims[name])))

                    found = False
                    got_scopes = claims[name].split()
                    for s in got_scopes:
                        if s == value:
                            found = True
                            break

                    if not found:
                        raise JWTInvalidClaimValue(
                            "Invalid '%s' value. Scope list '%s' does not "
                            "contain the required scope '%s'" % (
                                name, claims[name], value))
            else:
                if value is not None and value != claims[name]:
                    raise JWTInvalidClaimValue(
                        "Invalid '%s' value. Expected '%s' got '%s'" % (
                            name, value, claims[name]))

    def norm_typ(self, val):
        lc = val.lower()
        if '/' in lc:
            return lc
        else:
            return 'application/' + lc

    def make_signed_token(self, key):
        """Signs the payload.

        Creates a JWS token with the header as the JWS protected header and
        the claims as the payload. See (:class:`jwcrypto.jws.JWS`) for
        details on the exceptions that may be raised.

        :param key: A (:class:`jwcrypto.jwk.JWK`) key.
        """

        t = JWS(self.claims)
        if self._algs:
            t.allowed_algs = self._algs
        t.add_signature(key, protected=self.header)
        self.token = t
        self._expected_type = "JWS"

    def make_encrypted_token(self, key):
        """Encrypts the payload.

        Creates a JWE token with the header as the JWE protected header and
        the claims as the plaintext. See (:class:`jwcrypto.jwe.JWE`) for
        details on the exceptions that may be raised.

        :param key: A (:class:`jwcrypto.jwk.JWK`) key.
        """

        t = JWE(self.claims, self.header)
        if self._algs:
            t.allowed_algs = self._algs
        t.add_recipient(key)
        self.token = t
        self._expected_type = "JWE"

    def validate(self, key):
        """Validate a JWT token that was deserialized w/o providing a key

        :param key: A (:class:`jwcrypto.jwk.JWK`) verification or
         decryption key, or a (:class:`jwcrypto.jwk.JWKSet`) that
         contains a key indexed by the 'kid' header.
        """
        self.deserializelog = []
        if self.token is None:
            raise ValueError("Token empty")

        et = self._expected_type_heuristics(key)
        validate_fn = None

        if isinstance(self.token, JWS):
            if et != "JWS" and JWT_expect_type:
                raise TypeError("Expected {}, got JWS".format(et))
            validate_fn = self.token.verify
        elif isinstance(self.token, JWE):
            if et != "JWE" and JWT_expect_type:
                raise TypeError("Expected {}, got JWE".format(et))
            validate_fn = self.token.decrypt
        else:
            raise ValueError("Token format unrecognized")

        try:
            validate_fn(key)
            self.deserializelog.append("Success")
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(self.token, JWS):
                self.deserializelog = self.token.verifylog
            elif isinstance(self.token, JWE):
                self.deserializelog = self.token.decryptlog
            self.deserializelog.append(
                'Validation failed: [{}]'.format(repr(e)))
            if isinstance(e, JWKeyNotFound):
                raise JWTMissingKey() from e
            raise

        self.header = self.token.jose_header
        payload = self.token.payload
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8')
        self.claims = payload
        self._check_provided_claims()

    @staticmethod
    def _is_json_serialization(jwt):
        # The JWS/JWE Compact Serialization is a sequence of base64url
        # encoded parts joined by dots, so it never decodes as a JSON
        # object. The JWS/JWE JSON Serialization always is a JSON object.
        # This mirrors how JWS.deserialize and JWE.deserialize themselves
        # tell the two representations apart.
        try:
            return isinstance(json_decode(jwt), dict)
        except ValueError:
            return False

    def deserialize(self, jwt, key=None):
        """Deserialize a JWT token.

        NOTE: Destroys any current status and tries to import the raw
        token provided.

        :param jwt: a 'raw' JWT token.
        :param key: A (:class:`jwcrypto.jwk.JWK`) verification or
         decryption key, or a (:class:`jwcrypto.jwk.JWKSet`) that
         contains a key indexed by the 'kid' header.

        :raises ValueError: if strict_serialization is enabled and the
         token is not in the JWS/JWE Compact Serialization (for example
         when a JSON Serialization is provided).
        """
        if self._strict_serialization and self._is_json_serialization(jwt):
            raise ValueError("Only the JWS/JWE Compact Serialization is "
                             "allowed for JWTs (RFC 7519), but a JSON "
                             "Serialization was provided")

        data = jwt.count('.')
        if data == 2:
            self.token = JWS()
        elif data == 4:
            self.token = JWE()
        else:
            raise ValueError("Token format unrecognized")

        # Apply algs restrictions if any, before performing any operation
        if self._algs:
            self.token.allowed_algs = self._algs

        self.deserializelog = None
        # now deserialize and also decrypt/verify (or raise) if we
        # have a key
        self.token.deserialize(jwt, None)
        if key:
            self.validate(key)

    def serialize(self, compact=True):
        """Serializes the object into a JWS token.

        :param compact(boolean): must be True.

        Note: the compact parameter is provided for general compatibility
        with the serialize() functions of :class:`jwcrypto.jws.JWS` and
        :class:`jwcrypto.jwe.JWE` so that these objects can all be used
        interchangeably. However the only valid JWT representation is the
        compact representation.

        :return: A json formatted string or a compact representation string
        :rtype: `str`
        """
        if not compact:
            raise ValueError("Only the compact serialization is allowed")

        return self.token.serialize(compact)

    @classmethod
    def from_jose_token(cls, token):
        """Creates a JWT object from a serialized JWT token.

        :param token: A string with the json or compat representation
         of the token.

        :raises InvalidJWEData or InvalidJWSObject: if the raw object is an
         invalid JWT token.

        :return: A JWT token
        :rtype: JWT
        """

        obj = cls()
        obj.deserialize(token)
        return obj

    def __eq__(self, other):
        if not isinstance(other, JWT):
            return False
        return self._claims == other._claims and \
            self._header == other._header and \
            self.token == other.token

    def __str__(self):
        try:
            return self.serialize()
        except Exception:  # pylint: disable=broad-except
            return self.__repr__()

    def __repr__(self):
        jwt = repr(self.token)
        return f'JWT(header={self._header}, ' + \
               f'claims={self._claims}, ' + \
               f'jwt={jwt}, ' + \
               f'key=None, algs={self._algs}, ' + \
               f'default_claims={self._reg_claims}, ' + \
               f'check_claims={self._check_claims})'


class NestedJWT(JWT):
    """Nested JSON Web Token object (RFC 7519, Section 5.2).

    This object represents a nested JWT: a signed JWT (JWS) that is
    encapsulated as the plaintext of an encrypted JWT (JWE). Only the
    "sign, then encrypt" order is supported, and only the JWS/JWE
    Compact Serializations are accepted.

    The two layers are validated strictly in order and independently:
    the outer JWE is authenticated first, and only then is the inner
    JWS parsed and verified. Claims are exposed (and issuer, audience
    and time based checks performed) only after the inner signature
    has been successfully verified. The key used to verify the inner
    JWS always comes from the caller provided 'inner_key' parameter;
    header parameters of the outer JWE are never used to select the
    inner verification key.
    """

    # A nested JWT is exactly two layers deep: a JWS inside a JWE.
    # Deeper nesting is never attempted.
    MAX_NESTING_DEPTH = 2

    def __init__(self, header=None, claims=None, jwt=None,
                 outer_key=None, inner_key=None,
                 outer_algs=None, inner_algs=None,
                 expected_outer_typ=None, expected_outer_cty='JWT',
                 expected_inner_typ='JWT',
                 max_payload_size=None,
                 default_claims=None, check_claims=None):
        """Creates a NestedJWT object.

        :param header: A dict or a JSON string with the JWS Header
         data for the inner (signed) token, used when creating a token
         with :meth:`make_nested_token`. A 'typ' of "JWT"" is added
         if not present.
        :param claims: A dict or a string with the JWT Claims data,
         used when creating a token with :meth:`make_nested_token`.
        :param jwt: a 'raw' nested JWT token to validate. Both
         'outer_key' and 'inner_key' must be provided when 'jwt' is.
        :param outer_key: A (:class:`jwcrypto.jwk.JWK`) decryption key
         for the outer JWE, or a (:class:`jwcrypto.jwk.JWKSet`) that
         contains a key indexed by the 'kid' header of the outer JWE.
        :param inner_key: A (:class:`jwcrypto.jwk.JWK`) verification
         key for the inner JWS, or a (:class:`jwcrypto.jwk.JWKSet`)
         that contains a key indexed by the 'kid' header of the inner
         JWS. This is the only source of keys for the inner layer.
        :param outer_algs: An optional list of allowed algorithms for
         the outer JWE. If not provided the JWE default allowed
         algorithms apply.
        :param inner_algs: An optional list of allowed algorithms for
         the inner JWS. If not provided the JWS default allowed
         algorithms apply.
        :param expected_outer_typ: An optional string with the expected
         value of the 'typ' header parameter of the outer JWE. The
         comparison is case-insensitive and ignores an optional
         'application/' prefix. If None (default) the parameter is not
         checked.
        :param expected_outer_cty: An optional string with the expected
         value of the 'cty' header parameter of the outer JWE, compared
         like 'typ'. Defaults to "JWT" as required by RFC 7519,
         Section 5.2. Set to None to disable the check.
        :param expected_inner_typ: An optional string with the
         expected value of the 'typ' header parameter of the inner JWS,
         compared like 'typ'. Defaults to "JWT". Set to None to disable
         the check.
        :param max_payload_size: Maximum size in bytes of the decrypted
         outer payload (the serialized inner token). When the outer JWE
         uses compression this also bounds the total decompressed size.
         Defaults to 256 KiB.
        :param default_claims: An optional dict with default values for
         registered claims, see :class:`JWT`.
        :param check_claims: An optional dict of claims that must be
         present in the validated inner token, see :class:`JWT`. Time
         based claims ('exp', 'nbf') can be pinned to a fixed
         reference time by providing an explicit value.

        Note: if check_claims is not provided the 'exp' and 'nbf'
        claims are checked against the current time if they are set on
        the token but not enforced if not set.
        """
        self._outer_algs = outer_algs
        self._inner_algs = inner_algs
        self._expected_outer_typ = expected_outer_typ
        self._expected_outer_cty = expected_outer_cty
        self._expected_inner_typ = expected_inner_typ
        if max_payload_size is None:
            max_payload_size = default_max_nested_payload_size
        self._max_payload_size = int(max_payload_size)
        self._outer_token = None
        self._inner_token = None
        super(NestedJWT, self).__init__(
            header=header, claims=claims,
            default_claims=default_claims, check_claims=check_claims)
        if jwt is not None:
            self.deserialize(jwt, outer_key=outer_key, inner_key=inner_key)

    @property
    def outer_token(self):
        """The validated outer :class:`jwcrypto.jwe.JWE` token."""
        return self._outer_token

    @property
    def inner_token(self):
        """The validated inner :class:`jwcrypto.jws.JWS` token."""
        return self._inner_token

    @property
    def outer_header(self):
        """The JOSE header of the outer JWE, as a dict."""
        if self._outer_token is None:
            raise KeyError("'outer_header' not set")
        return self._outer_token.jose_header

    def _reset_nested_state(self):
        self._header = None
        self._claims = None
        self._token = None
        self._outer_token = None
        self._inner_token = None
        self.deserializelog = None

    def _check_header_parameter(self, header, name, expected, layer):
        if expected is None:
            return
        actual = header.get(name)
        if actual is None:
            raise JWTInvalidHeaderParameter(
                "Missing '%s' header parameter in the %s" % (name, layer))
        if not isinstance(actual, str) or \
                self.norm_typ(actual) != self.norm_typ(expected):
            raise JWTInvalidHeaderParameter(
                "Invalid '%s' header parameter in the %s. "
                "Expected '%s' got '%s'" % (name, layer, expected, actual))

    def make_nested_token(self, inner_key, outer_key, outer_header=None):
        """Signs the claims and then encrypts the signed token.

        Creates an inner JWS with the object header as its protected
        header and the object claims as its payload, then wraps it in
        an outer JWE. A 'cty' of "JWT" is added to the outer protected
        header if not present, as required by RFC 7519, Section 5.2.

        :param inner_key: A (:class:`jwcrypto.jwk.JWK`) signing key.
        :param outer_key: A (:class:`jwcrypto.jwk.JWK`) encryption key.
        :param outer_header: An optional dict with the JWE protected
         header data. It must contain suitable 'alg' and 'enc' values.
        """
        inner_header = {}
        if self._header is not None:
            inner_header = json_decode(self._header)
        inner_header.setdefault('typ', 'JWT')
        inner = JWS(self.claims)
        if self._inner_algs is not None:
            inner.allowed_algs = self._inner_algs
        inner.add_signature(inner_key, protected=json_encode(inner_header))
        signed = inner.serialize(compact=True)

        oh = dict(outer_header) if outer_header else {}
        oh.setdefault('cty', 'JWT')
        outer = JWE(signed.encode('utf-8'), protected=json_encode(oh))
        if self._outer_algs is not None:
            outer.allowed_algs = self._outer_algs
        outer.add_recipient(outer_key)

        self._inner_token = inner
        self._outer_token = outer
        self.token = outer

    def deserialize(self, jwt, outer_key=None, inner_key=None):
        """Deserialize and validate a nested JWT token.

        NOTE: Destroys any current status and tries to import and
        validate the raw token provided. If any validation step fails
        an exception is raised and no claims or headers are exposed on
        the object.

        :param jwt: a 'raw' nested JWT token.
        :param outer_key: A (:class:`jwcrypto.jwk.JWK`) decryption key
         for the outer JWE, or a (:class:`jwcrypto.jwk.JWKSet`) that
         contains a key indexed by the 'kid' header of the outer JWE.
        :param inner_key: A (:class:`jwcrypto.jwk.JWK`) verification
         key for the inner JWS, or a (:class:`jwcrypto.jwk.JWKSet`)
         that contains a key indexed by the 'kid' header of the inner
         JWS.

        :raises ValueError: if the token is not a nested JWT in the
         JWE Compact Serialization, or if the keys are not provided.
        """
        if outer_key is None or inner_key is None:
            raise ValueError("Both 'outer_key' and 'inner_key' are "
                             "required to validate a nested JWT")
        self._reset_nested_state()
        try:
            self._deserialize_nested(jwt, outer_key, inner_key)
        except Exception:
            # Never leave partially validated, potentially attacker
            # controlled state behind on failure.
            self._reset_nested_state()
            raise

    def _deserialize_nested(self, jwt, outer_key, inner_key):
        # The outer layer must be a JWE in Compact Serialization. The
        # format is never guessed: anything else is rejected outright
        # instead of trying other interpretations.
        if self._is_json_serialization(jwt):
            raise ValueError("Only the JWE Compact Serialization is "
                             "allowed for the outer token of a nested "
                             "JWT, but a JSON Serialization was provided")
        if jwt.count('.') != 4:
            raise ValueError("A nested JWT must have an outer JWE in "
                             "Compact Serialization (5 parts)")

        outer = JWE()
        if self._outer_algs is not None:
            outer.allowed_algs = self._outer_algs
        outer.deserialize(jwt)
        # max_plaintext bounds the decompressed size when the outer
        # JWE uses compression.
        outer.decrypt(outer_key, max_plaintext=self._max_payload_size)

        # The outer layer is authenticated at this point. Enforce the
        # typ/cty policy before looking at the content.
        outer_header = outer.jose_header
        self._check_header_parameter(outer_header, 'cty',
                                     self._expected_outer_cty,
                                     'outer JWE')
        self._check_header_parameter(outer_header, 'typ',
                                     self._expected_outer_typ,
                                     'outer JWE')

        payload = outer.payload
        if len(payload) > self._max_payload_size:
            raise InvalidJWEData(
                'Nested JWT payload exceeds maximum allowed size'
                f' ({self._max_payload_size})')
        if isinstance(payload, bytes):
            inner_jwt = payload.decode('utf-8')
        else:
            inner_jwt = payload

        # The inner layer must be a JWS in Compact Serialization. This
        # also enforces the nesting depth limit: a nested JWT is
        # exactly a JWS inside a JWE, anything else (including a
        # further nested token) is rejected.
        if self._is_json_serialization(inner_jwt) or \
                inner_jwt.count('.') != 2:
            raise ValueError("The inner token of a nested JWT must be "
                             "a JWS in Compact Serialization (3 parts)")

        inner = JWS()
        if self._inner_algs is not None:
            inner.allowed_algs = self._inner_algs
        inner.deserialize(inner_jwt)
        # The verification key comes exclusively from the caller
        # provided inner_key; the outer header is never consulted to
        # select it.
        inner.verify(inner_key)

        # The inner signature is verified at this point.
        inner_header = inner.jose_header
        self._check_header_parameter(inner_header, 'typ',
                                     self._expected_inner_typ,
                                     'inner JWS')

        claims = inner.payload
        if isinstance(claims, bytes):
            claims = claims.decode('utf-8')

        # Both layers are validated; only now expose the token, the
        # headers and the claims, and run the claims checks (issuer,
        # audience, expiration, etc).
        self._inner_token = inner
        self._outer_token = outer
        self.token = outer
        self.header = inner_header
        self.claims = claims
        self._check_provided_claims()
