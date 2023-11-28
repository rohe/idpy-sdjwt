from typing import List

from cryptojwt import JWT
from cryptojwt import KeyJar
from cryptojwt.exception import VerificationError
from cryptojwt.jwk import DIGEST_HASH
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import SIGNER_ALGS
from cryptojwt.jws.jws import factory
from idpysdjwt.disclosure import parse_disclosure


class Verifier(JWT):

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
            sdjwt: str = "",
    ):

        JWT.__init__(self,
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
                     )
        if allowed_sign_algs is None:
            allowed_sign_algs = list(SIGNER_ALGS.keys())
            allowed_sign_algs.remove('none')

        self.payload = {}
        self.jwt = None
        self.aud = ""
        self._hash_dict = {}
        self.sdjwt = sdjwt
        if sdjwt:
            self.parse(sdjwt)

    def _expand_array_disclosure(self, val):
        res = []
        for v in val:
            if isinstance(v, dict) and "..." in v:
                _val = self.disclosure_by_hash.get(v["..."])
                if _val:
                    res.append(_val[1])
            else:
                res.append(v)
        return res

    def _process(self, item: dict) -> dict:
        res = {}

        for _hash in item.get("_sd", []):
            _val = self.disclosure_by_hash.get(_hash)
            if _val:
                res.update({_val[1]: _val[2]})

        for k, v in item.items():
            if k in ['_sd', '_sd_alg']:
                continue

            if isinstance(v, dict):
                res[k] = self._process(v)
            elif isinstance(v, list):
                res[k] = self._expand_array_disclosure(v)
            else:
                res[k] = v

        return res

    def evaluate(self, jwt_payload: dict, selective_disclosures: dict = None):
        _discl = [parse_disclosure(d, hash_func='sha-256') for d in selective_disclosures]
        self.disclosure_by_hash = {_hash: _disc for _disc, _hash in _discl}

        res = self._process(jwt_payload)

        return res

    def parse(self, msg):
        self.sdjwt = msg
        _part = msg.split("~")

        # deal with the signed JSON Web Token
        self.jwt = self.unpack(_part[0])

        # Bring in the disclosures to calculate the payload

        self.payload = self.evaluate(self.jwt, _part[1:-1])

        if _part[-1]:  # holder of key JWT
            # This is the key that is carried in the JWT signed by the issuer
            # The key belongs to the holder
            _key = key_from_jwk_dict(self.jwt["cnf"]["jwk"])

            self.key_jar.add_keys(issuer_id="", keys=[_key])
            _holder_of_key = self.unpack(_part[-1])
            if not _holder_of_key:
                raise VerificationError("Could not verify holder of key JWT")
            else:
                self.payload_audience = _holder_of_key["aud"]

        if "_sd_alg" in self.payload:
            if self.payload['_sd_alg'] not in DIGEST_HASH:
                raise ValueError(f"Not recognized hash algorithm {self.payload['_sd_alg']}")


def display_sdjwt(msg):
    _part = msg.split("~")

    # deal with the signed JSON Web Token
    _payload = factory(_part[0]).jwt.payload()
    _discl = [parse_disclosure(d, hash_func='sha-256') for d in _part[1:-1]]
    return _payload, _discl
