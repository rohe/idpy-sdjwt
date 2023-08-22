import json
from typing import List

from cryptojwt import JWT
from cryptojwt import KeyJar
from idpysdjwt import SD_TYP
from idpysdjwt.disclosure import parse_disclosure
from idpysdjwt.payload import Payload


class SDJWT(JWT):

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
            holder_key: dict = None
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
        self.objective_disclosure = objective_disclosure
        self.array_disclosure = array_disclosure
        self.payload = Payload()
        self.holder_key = holder_key

    def message(self, signing_key, **kwargs):
        self.payload.args = kwargs

        self.payload.add_objects([], self.objective_disclosure)
        self.payload.add_arrays([], self.array_disclosure)

        _load = self.payload.create(hash_func='sha-256', signing_key=signing_key)
        return json.dumps(_load)

    def get_disclosure(self):
        if not self.payload.disclosure:
            return ""
        else:
            return self.payload.disclosure

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

    def evaluate(self, jwt_payload, selective_disclosures):
        _discl = [parse_disclosure(d, hash_func='sha-256') for d in selective_disclosures]
        self.disclosure_by_hash = {_hash: _disc for _disc, _hash in _discl}

        res = self._process(jwt_payload)

        return res

    def create_key_binding_jwt(self):
        return ""

    def create_message(self,
                       payload, jws_headers: dict = None,
                       key_binding: bool = False,
                       **kwargs):
        if jws_headers is None:
            jws_headers = {"typ": SD_TYP}
        elif 'typ' not in jws_headers:
            jws_headers['typ'] = SD_TYP

        _jws = self.pack(payload=payload, jws_headers=jws_headers, **kwargs)

        # The message format is
        # <JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>
        _parts = [_jws]
        _parts.extend(self.get_disclosure())
        if key_binding:
            # _jwt = factory(_jws)
            _parts.append(self.create_key_binding_jwt())
        else:
            _parts.append("")

        return "~".join(_parts)
