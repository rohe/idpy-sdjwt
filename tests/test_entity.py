
import os

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory

from idpysdjwt.entity import Sender
from idpysdjwt.jwt import SDJWT
from idpysdjwt.payload import evaluate_disclosure

ALICE = "https://example.org/alice"
BOB = "https://example.com/bob"
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


# k1 = import_private_rsa_key_from_file(full_path('rsa.key'))
# k2 = import_private_rsa_key_from_file(full_path('size2048.key'))

kb1 = KeyBundle(
    source="file://{}".format(full_path("rsa.key")),
    fileformat="der",
    keyusage="sig",
    kid="1",
)
kb2 = KeyBundle(
    source="file://{}".format(full_path("size2048.key")),
    fileformat="der",
    keyusage="enc",
    kid="2",
)

ALICE_KEY_JAR = KeyJar()
ALICE_KEY_JAR.add_kb(ALICE, kb1)
ALICE_KEY_JAR.add_kb(ALICE, kb2)

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


def test_sender():
    alice = Sender(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="RS256",
        lifetime=600,
        objective_disclosure=EndUserClaims,
        array_disclosure=SELDISC
    )

    payload = {"sub": "sub", "aud": BOB}
    _msg = alice.create_message(payload=payload, jws_headers={"typ": "example+sd-jwt"})

    # msg is what is sent to the receiver

    _part = _msg.split("~")
    assert len(_part) == 12

    # deal with the signed JSON Web Token
    _jwt = factory(_part[0])
    assert _jwt.jwt.headers["typ"] == "example+sd-jwt"
    assert _jwt.jwt.headers['alg'] == "RS256"

    _msg = _jwt.jwt.payload()
    assert "_sd" in _msg
    assert "_sd_alg" in _msg
    assert "cnf" in _msg
    assert "nationalities" in _msg and len(_msg["nationalities"]) == 2

    # Bring in the disclosures to calculate the payload

    kw = evaluate_disclosure(_msg, _part[1:-1])

    assert set(kw.keys()) == {'phone_number', 'updated_at', 'phone_number_verified', 'address',
                              'birthdate', 'family_name', 'email', 'given_name',
                              'exp', 'sub', 'iss', 'iat', 'nationalities', 'aud', 'cnf'}

    assert set(kw['nationalities']) == {"US", "DE"}


