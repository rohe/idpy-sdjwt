from typing import Any
from typing import List

from cryptojwt.jwk.asym import AsymmetricKey
from idpysdjwt.disclosure import ArrayDisclosure
from idpysdjwt.disclosure import ObjectDisclosure
from idpysdjwt.disclosure import parse_disclosure


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
            res = []
            for _discl, _hash in val.make(hash_func):
                self._disclosure.append(_discl)
                res.append({"...": f"{_hash}"})
            return res
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


def add_value(orig, new):
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


def evaluate_disclosure(jwt_payload, selective_disclosures):
    _discl = [parse_disclosure(d, hash_func='sha-256') for d in selective_disclosures]

    res = {}
    for _disc, _hash in _discl:
        if _hash in jwt_payload['_sd']:
            _key = _disc[1]
            _val = _disc[2]
            res[_key] = add_value(jwt_payload.get(_key), _val)
        else:
            _val = _disc[1]
            for k, vl in jwt_payload.items():
                if k.startswith('_'):
                    continue
                if k in res:
                    vl = res[k]

                if isinstance(vl, list):
                    match = False
                    rl = vl[:]
                    for v in vl:  # dictionary with '...' as key
                        if isinstance(v, dict) and len(v) == 1 and "..." in v:
                            if _hash == v['...']:
                                rl.remove(v)
                                rl.append(_val)
                                match = True
                            else:
                                pass
                    res[k] = rl
                    if match:
                        continue

    for key, val in jwt_payload.items():
        if key.startswith('_'):
            continue

        if key not in res:
            res[key] = val
        else:
            _val = [v for v in val if not(isinstance(v, dict) and len(v) == 1 and "..." in v)]
            if _val:
                res[key] = add_value(res[key], _val)

    return res
