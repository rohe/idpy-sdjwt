from typing import Any
from typing import List

from cryptojwt.jwk.asym import AsymmetricKey
from idpysdjwt.disclosure import ArrayDisclosure
from idpysdjwt.disclosure import ObjectDisclosure


class Payload(object):

    def __init__(self, **kwargs):
        self.args = kwargs
        self._disclosure = []
        self._hash = []

    def add_object_disclosure(self, key: str, value: str):
        _val = self.args.get(key)
        if _val:
            if isinstance(_val, list):
                self.args[key].append(ObjectDisclosure(value, key))
            else:
                _vals = [_val, ObjectDisclosure(value, key)]
                self.args[key] = _vals
        else:
            self.args[key] = ObjectDisclosure(value, key)

    def add_array_disclosure(self, key: str, value: list):
        _val = self.args.get(key)
        if _val:
            if isinstance(_val, list):
                self.args[key].append(ArrayDisclosure(value))
            else:
                self.args[key] = [_val, ArrayDisclosure(value)]
        else:
            self.args[key] = ArrayDisclosure(value)

    def _const(self, val, hash_func):
        if isinstance(val, ObjectDisclosure):
            _discl, _hash = val.make(hash_func)
            self._disclosure.append(_discl)
            self._hash.append(_hash)
            return None
        elif isinstance(val, ArrayDisclosure):
            _discl, _hash = val.make(hash_func)
            self._disclosure.extend(_discl)
            # self._hash.extend(_hash)
            return [{"...": f"{h}"} for h in _hash]
        else:
            return val

    def _construct(self, hash_func, args) -> List[Any]:
        res = []
        for val in args:
            if isinstance(val, list):
                vis = self._construct(hash_func, val)
            elif isinstance(val, ObjectDisclosure):
                vis = self._const(val, hash_func)
            elif isinstance(val, ArrayDisclosure):
                vis = self._const(val, hash_func)
            else:
                vis = val

            if vis:
                res.append(vis)
        return res

    def create(self, hash_func: str = "SHA-256", signing_key: AsymmetricKey = None):
        res = {}
        for key, val in self.args.items():
            if isinstance(val, list):
                vis = self._construct(hash_func, val)
            elif isinstance(val, ObjectDisclosure):
                vis = self._const(val, hash_func)
            elif isinstance(val, ArrayDisclosure):
                vis = self._const(val, hash_func)
            else:
                vis = val

            if vis:
                res[key] = vis

        self._hash.sort()
        res['_sd'] = self._hash
        res['_sd_alg'] = hash_func.lower()
        if signing_key:
            res['cnf'] = {
                "jwk": signing_key.serialize()
            }
        return res
