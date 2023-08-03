import json
import secrets
from typing import List

from cryptojwt import as_unicode
from cryptojwt import b64d
from cryptojwt import b64encode_item
from cryptojwt.jwk import DIGEST_HASH
from cryptojwt.utils import as_bytes
from cryptojwt.utils import b64e


def make_hash(disclosure, hash_func: str = "sha-256"):
    _hash = DIGEST_HASH[hash_func.upper()](disclosure)
    return as_unicode(b64encode_item(_hash))


def parse_disclosure(specification: str, hash_func: str = "sha-256") -> tuple:
    _disc = b64d(as_bytes(specification))
    _hash = make_hash(specification, hash_func)
    return json.loads(_disc), _hash


class Disclosure(object):

    def __init__(self):
        pass

    def make(self, salt) -> str:
        raise NotImplementedError()


class ObjectDisclosure(Disclosure):

    def __init__(self, value, name: str):
        Disclosure.__init__(self)
        self._name = name
        self._value = value

    def make(self, hash_func: str = "sha-256", salt: str = "") -> tuple:
        _salt = salt or as_unicode(b64e(secrets.token_bytes(16)))

        if self._name:
            _json_str = json.dumps([_salt, self._name, self._value])
        else:
            _json_str = json.dumps([_salt, self._value])
        _disclosure = as_unicode(b64e(as_bytes(_json_str)))
        return _disclosure, make_hash(_disclosure)


class ArrayDisclosure(Disclosure):

    def __init__(self, value):
        Disclosure.__init__(self)
        self._value = value

    def _make_single(self, val, salt: str = "") -> str:
        _salt = salt or as_unicode(b64e(secrets.token_bytes(16)))
        _json_str = json.dumps([_salt, val])
        return as_unicode(b64e(as_bytes(_json_str)))

    def make(self, hash_func: str = "sha-256", salt: List[str] = None) -> list:
        if salt:
            _disc_arr = [self._make_single(val, sal) for val, sal in zip(self._value, salt)]
        else:
            _disc_arr = [self._make_single(val) for val in self._value]

        return [(_d, make_hash(_d, hash_func)) for _d in _disc_arr]

