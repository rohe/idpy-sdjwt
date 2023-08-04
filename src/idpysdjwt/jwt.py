import json
from typing import List

from cryptojwt import JWT
from cryptojwt import KeyJar

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
            array_disclosure: dict = None
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

    def message(self, signing_key, **kwargs):
        self.payload.args = kwargs

        for key, val in self.objective_disclosure.items():
            self.payload.add_object_disclosure(key, val)

        for key, val in self.array_disclosure.items():
            self.payload.add_array_disclosure(key, val)

        _load = self.payload.create(hash_func='sha-256', signing_key=signing_key)
        return json.dumps(_load)

    def get_disclosure(self):
        return self.payload.disclosure
