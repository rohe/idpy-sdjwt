import json
from typing import List
from typing import Optional

from cryptojwt import JWK
from cryptojwt import JWT
from cryptojwt import KeyJar
from idpysdjwt import SD_TYP
from idpysdjwt.payload import Payload


class Issuer(JWT):

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
                       zip=zip)

        self.objective_disclosure = objective_disclosure
        self.array_disclosure = array_disclosure
        self.payload = Payload()
        self.holder_key = holder_key

    def add_object_disclosure(self, path: List[str], key: str, value):
        self.payload.add_object_disclosure(path, key, value)

    def add_array_disclosure(self, path: List[str], values: list):
        self.payload.add_array_disclosure(path, values)

    def create_holder_message(self,
                              payload: Optional[dict] = None,
                              jws_headers: Optional[dict] = None,
                              holder_key: Optional[dict] = None,
                              **kwargs) -> str:
        if jws_headers is None:
            jws_headers = {"typ": SD_TYP}
        elif 'typ' not in jws_headers:
            jws_headers['typ'] = SD_TYP

        _jwt = self.pack(payload=payload, jws_headers=jws_headers, **kwargs)

        # The message format is
        # <JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>
        _parts = [_jwt]
        _parts.extend(self.get_disclosure())
        # No key binding JWT from here
        _parts.append("")

        return "~".join(_parts)

    def message(self,
                signing_key: Optional[JWK] = None, # Not used
                holder_key: Optional[JWK] = None,
                **kwargs):
        self.payload.args = kwargs

        self.payload.add_objects([], self.objective_disclosure)
        self.payload.add_arrays([], self.array_disclosure)

        holder_key = holder_key or self.holder_key
        _load = self.payload.construct(hash_func='sha-256', holder_key=holder_key)
        return json.dumps(_load)

    def get_disclosure(self):
        if not self.payload.disclosure:
            return ""
        else:
            return self.payload.disclosure

