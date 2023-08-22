from idpysdjwt.disclosure import ObjectDisclosure
from idpysdjwt.disclosure import parse_disclosure
from idpysdjwt.payload import Payload


def test_disclosure_1():
    _claim = ObjectDisclosure("Möbius", "family_name")
    _disclosure, _hash = _claim.make(salt="_26bc4LT-ac6q2KI6cBW5es")
    assert _disclosure == (
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd")


def test_disclosure_2():
    _claim = ObjectDisclosure("FR", "")
    _disclosure, _hash = _claim.make(salt="lklxF5jMYlGTPUovMNIvCA")
    assert _disclosure == "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"


def test_hashed_disclosure_2():
    _claim = ObjectDisclosure("FR", "")
    _disc, _hash = _claim.make(salt="lklxF5jMYlGTPUovMNIvCA")
    assert _hash == "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"

    a, b = parse_disclosure(_disc)
    assert a == ['lklxF5jMYlGTPUovMNIvCA', 'FR']
    assert b == _hash


SELECTIVE_ATTRIBUTE_DISCLOSURE = {
    "": {
        "given_name": "John",
        "family_name": "Doe",
    },
    "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "country": "US"
    },
    "foo": {
        "bar": {
            "bell": True
        }
    }
}

SELECTIVE_ARRAY_DISCLOSURE = {
    "nationalities": ["US", "DE"],
    "team": {
        "group": ['A', 'B']
    }
}


def test_create_payload():
    payload = Payload(
        sub="user_42",
        iss="https://example.com/issuer",
        iat=1683000000,
        exp=1883000000,
        address={"country": "SE"}
    )
    payload.add_objects([], SELECTIVE_ATTRIBUTE_DISCLOSURE)
    payload.add_arrays([], SELECTIVE_ARRAY_DISCLOSURE)

    _payload = payload.create(hash_func='sha-256')

    assert set(_payload.keys()) == {'_sd', '_sd_alg', 'address', 'exp', 'foo',
                                    'iat', 'iss', 'nationalities', 'sub', 'team'}
    assert len(_payload['nationalities']) == 2
    assert len(_payload['_sd']) == 2
