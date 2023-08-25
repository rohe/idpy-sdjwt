from typing import List

from idpyoidc.util import rndstr

from .disclosure import b64_encode
from .verifier import Verifier


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
        # _jwt = JWT(self.key_jar, sign_alg=self.alg)
        return self.pack({'nonce': rndstr()}, aud=aud)

    def create_verifier_message(self,
                                disclosures: List[str],
                                key_holder_jwt: bool = False,
                                aud: str = ''):
        _in_part = self.sdjwt.split("~")
        _out_parts = [_in_part[0]]
        _out_parts.extend([b64_encode(self.disclosure_by_hash[_hash]) for _hash in disclosures])
        if key_holder_jwt:
            _out_parts.append(self.create_key_binding_jwt(aud))
        else:
            _out_parts.append('')
        return "~".join(_out_parts)
