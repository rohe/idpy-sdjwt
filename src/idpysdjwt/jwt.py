from cryptojwt import JWT

class SDJWT(JWT):
    def __init__(
            self,
            key_jar=None,
            iss="",
            lifetime=0,
            sign=True,
            sign_alg="RS256",
            encrypt=False,
            enc_enc="A128GCM",
            enc_alg="RSA-OAEP-256",
            msg_cls=None,
            iss2msg_cls=None,
            skew=15,
            allowed_sign_algs=None,
            allowed_enc_algs=None,
            allowed_enc_encs=None,
            zip="",
            selective_disclosure=None
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
