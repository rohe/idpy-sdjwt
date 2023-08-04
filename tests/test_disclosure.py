from idpysdjwt.disclosure import ObjectDisclosure
from idpysdjwt.disclosure import parse_disclosure
from idpysdjwt.payload import Payload
from idpysdjwt.payload import evaluate_disclosure


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


EndUserClaims = {
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "phone_number_verified": True,
    "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US"
    },
    "birthdate": "1940-01-01",
    "updated_at": 1570000000,
}

SELDISC = {
    "nationalities": [
        "US",
        "DE"
    ]
}


def test_create_payload():
    payload = Payload(
        sub="user_42",
        iss="https://example.com/issuer",
        iat=1683000000,
        exp=1883000000,
    )
    for key, val in EndUserClaims.items():
        payload.add_object_disclosure(key, val)

    for key, val in SELDISC.items():
        payload.add_array_disclosure(key, val)

    _payload = payload.create(hash_func='sha-256')

    assert set(_payload.keys()) == {'iss', 'nationalities', 'exp', '_sd', '_sd_alg', 'iat', 'sub'}
    assert len(_payload['nationalities']) == 2
    assert len(_payload['_sd']) == 8

    kw = evaluate_disclosure(_payload, payload._disclosure)

    assert set(kw.keys()) == {'phone_number', 'updated_at', 'phone_number_verified', 'address',
                              'birthdate', 'family_name', 'email', 'given_name',
                              'exp', 'sub', 'iss', 'iat', 'nationalities'}

    assert set(kw['nationalities']) == {"US", "DE"}
