from typing import Any
from typing import List

from cryptojwt.jwk.asym import AsymmetricKey
from idpysdjwt.disclosure import ArrayDisclosure
from idpysdjwt.disclosure import ObjectDisclosure


class Payload(object):

    def __init__(self, **kwargs):
        self.args = kwargs
        self.disclosure = []
        self.hash = []

    def find_start(self, path: List[str], end_item):
        if not path:
            _where = self.args
        else:
            _where = self.args
            for step in path[:-1]:
                _next = _where.get(step)
                if _next is None:
                    _where[step] = {}
                    _where = _where[step]

            step = path[-1]
            _next = _where.get(step)
            if _next is None:
                _where[step] = end_item

            _where = _where[step]

        return _where

    def add_objects(self, path, kwargs):
        for tag, item in kwargs.items():
            if tag == "":
                where = path
            else:
                where = path[:]
                where.append(tag)

            for key, val in item.items():
                if isinstance(val, dict):
                    self.add_objects(where, {key: val})
                else:
                    self.add_object_disclosure(where, key, val)

    def add_object_disclosure(self, path: List[str], key: str, value):
        _where = self.find_start(path, {})
        _val = _where.get('.')
        if _val:
            _where['.'].append(ObjectDisclosure(value, key))
        else:
            _where['.'] = [ObjectDisclosure(value, key)]

    def add_arrays(self, path, kwargs):
        for tag, item in kwargs.items():
            if tag == "":
                where = path
            else:
                where = path[:]
                where.append(tag)

            if isinstance(item, dict):
                self.add_arrays(where, item)
            else:
                self.add_array_disclosure(where, item)

    def add_array_disclosure(self, path: List[str], value: list):
        _where = self.find_start(path, [])
        _where.append(ArrayDisclosure(value))

    def _construct(self, hash_func, args) -> List[Any]:
        res = []
        for val in args:
            vis = None
            if isinstance(val, list):
                vis = self._construct(hash_func, val)
            elif isinstance(val, ArrayDisclosure):
                for _discl, _hash in val.make(hash_func):
                    self.disclosure.append(_discl)
                    res.append({"...": f"{_hash}"})
            else:
                vis = val

            if vis:
                res.append(vis)

        return res

    def _create(self, kwargs, hash_func: str = "SHA-256"):
        res = {}
        for key, val in kwargs.items():
            if key == ".":
                if "_sd" not in res:
                    res["_sd"] = []
                for v in val:
                    _discl, _hash = v.make(hash_func)
                    self.disclosure.append(_discl)
                    res["_sd"].append(_hash)
                res["_sd"].sort()
            else:
                if isinstance(val, dict):
                    vis = self._create(val, hash_func)
                elif isinstance(val, list):
                    vis = self._construct(hash_func, val)
                else:
                    vis = val

                if vis:
                    res[key] = vis

        return res

    def create(self, hash_func: str = "SHA-256", holder_key: AsymmetricKey = None):
        res = self._create(self.args, hash_func=hash_func)
        res['_sd_alg'] = hash_func.lower()
        if holder_key:
            res['cnf'] = {
                "jwk": holder_key.serialize()
            }
        return res
