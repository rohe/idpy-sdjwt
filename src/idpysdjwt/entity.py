from typing import List

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.jwk import DIGEST_HASH
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import SIGNER_ALGS
from idpyoidc.exception import VerificationError
from idpyoidc.util import rndstr
from idpysdjwt.jwt import SDJWT

from src.idpysdjwt.disclosure import b64_encode


class Issuer(SDJWT):

    def __init__(self,
                 key_jar: KeyJar = None,
                 iss: str = "",
                 lifetime: int = 0,
                 sign: bool = True,
                 sign_alg: str = "RS256",
                 encrypt: bool = False,
                 enc_enc: str = "A128GCM",
                 enc_alg: str = "RSA-OAEP-256",
                 msg_cls=None,
                 iss2msg_cls=None,
                 skew: int = 15,
                 allowed_sign_algs: List[str] = None,
                 allowed_enc_algs: List[str] = None,
                 allowed_enc_encs: List[str] = None,
                 zip: str = "",
                 objective_disclosure: dict = None,
                 array_disclosure: dict = None,
                 holder_key: dict = None
                 ):
        SDJWT.__init__(self,
                       key_jar=key_jar,
                       iss=iss,
                       lifetime=lifetime,
                       sign=sign,
                       sign_alg=sign_alg,
                       encrypt=encrypt,
                       enc_enc=enc_enc,
                       enc_alg=enc_alg,
                       msg_cls=msg_cls,
                       iss2msg_cls=iss2msg_cls,
                       skew=skew,
                       allowed_sign_algs=allowed_sign_algs,
                       allowed_enc_algs=allowed_enc_algs,
                       allowed_enc_encs=allowed_enc_encs,
                       zip=zip,
                       objective_disclosure=objective_disclosure,
                       array_disclosure=array_disclosure,
                       holder_key=holder_key)

    def add_object_disclosure(self, key: str, value: str):
        self.payload.add_object_disclosure(key, value)

    def add_array_disclosure(self, key: str, value: str):
        self.payload.add_array_disclosure(key, value)


class Verifier(SDJWT):

    def __init__(
            self,
            key_jar: KeyJar = None,
            iss: str = "",
            lifetime: int = 0,
            sign: bool = True,
            sign_alg: str = "RS256",
            encrypt: bool = False,
            enc_enc: str = "A128GCM",
            enc_alg: str = "RSA-OAEP-256",
            msg_cls=None,
            iss2msg_cls=None,
            skew: int = 15,
            allowed_sign_algs: List[str] = None,
            allowed_enc_algs: List[str] = None,
            allowed_enc_encs: List[str] = None,
            zip: str = "",
            objective_disclosure: dict = None,
            array_disclosure: dict = None,
            message: str = ""
    ):

        SDJWT.__init__(self,
                       key_jar=key_jar,
                       iss=iss,
                       lifetime=lifetime,
                       sign=sign,
                       sign_alg=sign_alg,
                       encrypt=encrypt,
                       enc_enc=enc_enc,
                       enc_alg=enc_alg,
                       msg_cls=msg_cls,
                       iss2msg_cls=iss2msg_cls,
                       skew=skew,
                       allowed_sign_algs=allowed_sign_algs,
                       allowed_enc_algs=allowed_enc_algs,
                       allowed_enc_encs=allowed_enc_encs,
                       zip=zip,
                       objective_disclosure=objective_disclosure,
                       array_disclosure=array_disclosure
                       )
        if allowed_sign_algs is None:
            allowed_sign_algs = list(SIGNER_ALGS.keys())
            allowed_sign_algs.remove('none')

        self.payload = {}
        self.jwt = None
        self.aud = ""
        self._hash_dict = {}
        self.message = message
        if message:
            self.parse(message)

    def parse(self, msg):
        self.message = msg
        _part = msg.split("~")

        # deal with the signed JSON Web Token
        self.jwt = self.unpack(_part[0])

        # Bring in the disclosures to calculate the payload

        self.payload = self.evaluate(self.jwt, _part[1:-1])

        if _part[-1]:  # holder of key JWT
            _key = key_from_jwk_dict(self.jwt["cnf"]["jwk"])
            _keyjar = KeyJar()
            _keyjar.add_keys(issuer_id="", keys=[_key])

            _jwt = JWT(key_jar=_keyjar)
            _holder_of_key = _jwt.unpack(_part[-1])
            if not _holder_of_key:
                raise VerificationError("Could not verify holder of key JWT")
            else:
                self.payload_audience = _holder_of_key["aud"]

        if "_sd_alg" in self.payload:
            if self.payload['_sd_alg'] not in DIGEST_HASH:
                raise ValueError(f"Not recognized hash algorithm {self.payload['_sd_alg']}")


class Holder(Verifier):

    def add_value(self, orig, new):
        if orig:
            if isinstance(orig, list):
                if isinstance(new, list):
                    orig.extend(new)
                else:
                    orig.append(new)
            else:
                orig = [orig]
                if isinstance(new, list):
                    orig.extend(new)
                else:
                    orig.append(new)
            return orig
        else:
            return new

    def create_key_binding_jwt(self, aud: str) -> str:
        _jwt = JWT(self.key_jar, sign_alg=self.alg)
        return _jwt.pack({'nonce': rndstr()}, aud=aud)

    def send(self, disclosures: List[str], key_holder_jwt: bool = False, aud: str = ''):
        _in_part = self.message.split("~")
        _out_parts = [_in_part[0]]
        _out_parts.extend([b64_encode(self.disclosure_by_hash[_hash]) for _hash in disclosures])
        if key_holder_jwt:
            _out_parts.append(self.create_key_binding_jwt(aud))
        else:
            _out_parts.append('')
        return "~".join(_out_parts)
