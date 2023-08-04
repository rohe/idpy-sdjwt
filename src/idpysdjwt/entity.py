from typing import List

from cryptojwt import KeyJar
from cryptojwt.jwk import DIGEST_HASH
from cryptojwt.jws.jws import SIGNER_ALGS

from idpysdjwt import SD_TYP
from idpysdjwt.jwt import SDJWT
from idpysdjwt.payload import evaluate_disclosure


class Sender(SDJWT):

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
                 array_disclosure: dict = None
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

    def add_object_disclosure(self, key: str, value: str):
        self.payload.add_object_disclosure(key, value)

    def add_array_disclosure(self, key: str, value: str):
        self.payload.add_array_disclosure(key, value)

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


class Receiver(SDJWT):

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

    def parse(self, msg):
        _part = msg.split("~")

        # deal with the signed JSON Web Token
        self.jwt = self.unpack(_part[0])

        # Bring in the disclosures to calculate the payload

        self.payload = evaluate_disclosure(self.jwt, _part[1:-1])

        if "_sd_alg" in self.payload:
            if self.payload['_sd_alg'] not in DIGEST_HASH:
                raise ValueError(f"Not recognized hash algorithm {self.payload['_sd_alg']}")