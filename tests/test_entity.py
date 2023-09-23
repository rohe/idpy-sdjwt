import os

from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from idpysdjwt.holder import Holder
from idpysdjwt.issuer import Issuer
from idpysdjwt.verifier import Verifier

ALICE = "https://example.org/issuer"
BOB = "https://example.com/holder"
CHARLIE = 'https://example.com/verifier'  # Charlie

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


ALICE_KEY_JAR = build_keyjar([{"type": "EC", "crv": "P-256", "use": ["sig"]}])
_priv_jwks = ALICE_KEY_JAR.export_jwks(private=True)
ALICE_KEY_JAR.import_jwks(_priv_jwks, ALICE)

BOB_KEY_JAR = build_keyjar([{"type": "EC", "crv": "P-256", "use": ["sig"]}])

# For these checks doesn't need key of their own.
CHARLIE_KEY_JAR = KeyJar()

_pub_jwks = ALICE_KEY_JAR.export_jwks()
# Load the alice's keys
BOB_KEY_JAR.import_jwks(_pub_jwks, ALICE)
CHARLIE_KEY_JAR.import_jwks(_pub_jwks, ALICE)

SELECTIVE_ATTRIBUTE_DISCLOSURES = {
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

SELECTIVE_ARRAY_DISCLOSURES = {
    "nationalities": ["US", "DE"],
    "team": {
        "group": ['A', 'B']
    }
}


def test_issuer():
    alice = Issuer(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="ES256",
        lifetime=600,
        objective_disclosure=SELECTIVE_ATTRIBUTE_DISCLOSURES,
        array_disclosure=SELECTIVE_ARRAY_DISCLOSURES
    )

    payload = {"sub": "sub", "aud": BOB}
    _msg = alice.create_holder_message(payload=payload, jws_headers={"typ": "example+sd-jwt"})

    # msg is what is sent to the receiver

    _part = _msg.split("~")
    assert len(_part) == 12

    # deal with the signed JSON Web Token
    _jwt = factory(_part[0])
    assert _jwt.jwt.headers["typ"] == "example+sd-jwt"
    assert _jwt.jwt.headers['alg'] == "ES256"

    _msg = _jwt.jwt.payload()
    assert "_sd" in _msg
    assert "_sd_alg" in _msg
    assert "nationalities" in _msg and len(_msg["nationalities"]) == 2


def test_issuer_2():
    alice = Issuer(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="ES256",
        lifetime=600,
        objective_disclosure={"": {}},
        array_disclosure=SELECTIVE_ARRAY_DISCLOSURES
    )

    payload = {"sub": "sub", "aud": BOB}
    _msg = alice.create_holder_message(payload=payload, jws_headers={"typ": "example+sd-jwt"})

    # msg is what is sent to the receiver

    _part = _msg.split("~")
    assert len(_part) == 12

    # deal with the signed JSON Web Token
    _jwt = factory(_part[0])
    assert _jwt.jwt.headers["typ"] == "example+sd-jwt"
    assert _jwt.jwt.headers['alg'] == "ES256"

    _msg = _jwt.jwt.payload()
    assert "_sd" in _msg
    assert "_sd_alg" in _msg
    assert "nationalities" in _msg and len(_msg["nationalities"]) == 2

def test_issuer_holder():
    alice = Issuer(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="ES256",
        lifetime=600,
        objective_disclosure=SELECTIVE_ATTRIBUTE_DISCLOSURES,
        array_disclosure=SELECTIVE_ARRAY_DISCLOSURES
    )

    payload = {"sub": "sub", "aud": BOB}
    _msg = alice.create_holder_message(payload=payload, jws_headers={"typ": "example+sd-jwt"})

    # msg is what is sent to the receiver

    bob = Holder(key_jar=BOB_KEY_JAR)
    bob.parse(_msg)

    assert set(bob.payload.keys()) == {'address', 'aud', 'exp', 'family_name', 'team',
                                       'foo', 'given_name', 'iat', 'iss', 'nationalities', 'sub'}

    assert set(bob.payload['nationalities']) == {"US", "DE"}


# key taken from Daniel Fett's implementation. Which is used to create the examples in the draft
ISSUER__JWKS = {
    "keys": [{
        "kty": "EC",
        "d": "Ur2bNKuBPOrAaxsRnbSH6hIhmNTxSGXshDSUD1a1y7g",
        "crv": "P-256",
        "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
        "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
    }]
}

ISSUER_ID = 'https://example.com/issuer'
BOB_KEY_JAR.import_jwks(ISSUER__JWKS, issuer=ISSUER_ID)


def test_receiver_msg_1():
    # Message from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

    msg = ("eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkd"
           "DJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5d"
           "TVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHb"
           "EFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3Jae"
           "mZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS"
           "0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFI"
           "iwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAia"
           "nN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzI"
           "jogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsI"
           "CJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllc"
           "yI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHe"
           "mhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlc"
           "lAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siO"
           "iB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IR"
           "jRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIV"
           "ldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub"
           "-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~Wy"
           "IyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlb"
           "HVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3"
           "dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20i"
           "XQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yM"
           "DItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bW"
           "Jlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZ"
           "HJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5I"
           "jogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMif"
           "V0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxL"
           "TAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwM"
           "DAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUk"
           "ZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~")

    bob = Verifier(key_jar=BOB_KEY_JAR)
    bob.parse(msg)
    assert set(bob.payload.keys()) == {'address', 'birthdate', 'cnf', 'email', 'exp',
                                       'family_name', 'given_name', 'iat', 'iss', 'nationalities',
                                       'phone_number', 'phone_number_verified', 'sub', 'updated_at'}
    assert bob.payload['nationalities'] == ['US', 'DE']
    assert bob.payload['birthdate'] == '1940-01-01'
    assert len(bob.disclosure_by_hash.keys()) == 10


def test_receiver_msg_2():
    # Message from https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

    msg = ("eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkd"
           "DJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5d"
           "TVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHb"
           "EFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3Jae"
           "mZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS"
           "0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFI"
           "iwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAia"
           "nN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzI"
           "jogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsI"
           "CJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllc"
           "yI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHe"
           "mhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlc"
           "lAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siO"
           "iB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IR"
           "jRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIV"
           "ldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub"
           "-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg"
           "~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd"
           "~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzI"
           "jogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogI"
           "kFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0"
           "~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
           "~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0"
           "~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI"
           "6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWV"
           "yIiwgImlhdCI6IDE2ODgxNjA0ODN9.tKnLymr8fQfupOgvMgBK3GCEIDEzhgta4MgnxY"
           "m9fWGMkqrz2R5PSkv0I-AXKXtIF6bdZRbjL-t43vC87jVoZQ")

    bob = Verifier(key_jar=BOB_KEY_JAR)
    bob.parse(msg)
    assert set(bob.payload.keys()) == {'address', 'cnf', 'exp', 'family_name',
                                       'given_name', 'iat', 'iss', 'nationalities', 'sub'}

    assert bob.payload['family_name'] == "Doe"
    assert bob.payload['given_name'] == "John"
    assert bob.payload['address'] == {'country': 'US',
                                      'locality': 'Anytown',
                                      'region': 'Anystate',
                                      'street_address': '123 Main St'}
    assert bob.payload['nationalities'] == ['US']

    assert len(bob.disclosure_by_hash.keys()) == 4


def test_issuer_holder_verifier():
    # Issuer
    alice = Issuer(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="ES256",
        lifetime=600,
        objective_disclosure=SELECTIVE_ATTRIBUTE_DISCLOSURES,
        array_disclosure=SELECTIVE_ARRAY_DISCLOSURES
    )

    payload = {"sub": "sub", "aud": BOB}
    _msg = alice.create_holder_message(payload=payload, jws_headers={"typ": "example+sd-jwt"})

    # Holder
    bob = Holder(key_jar=BOB_KEY_JAR)
    bob.parse(_msg)

    # Send to Verifier

    # List of hashes that maps to disclosures
    release = [['given_name', "John"], ["family_name", "Doe"]]
    _disclose = []
    for attr, val in release:
        for _hash, _spec in bob.disclosure_by_hash.items():
            if attr == _spec[1] and val == _spec[2]:
                _disclose.append(_hash)

    _msg = bob.create_verifier_message(_disclose)
    assert _msg

    # Verifier
    charlie = Verifier(key_jar=CHARLIE_KEY_JAR)
    charlie.parse(_msg)
    assert charlie.aud == ""  # There is no key binding JWT
    assert len(charlie.disclosure_by_hash) == 2
    assert charlie.payload['address'] == {}
    assert charlie.payload['nationalities'] == []


def test_issuer_holder_verifier_holder_of_key():
    # Issuer
    alice = Issuer(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="ES256",
        lifetime=600,
        objective_disclosure=SELECTIVE_ATTRIBUTE_DISCLOSURES,
        array_disclosure=SELECTIVE_ARRAY_DISCLOSURES,
        holder_key=BOB_KEY_JAR.get_signing_key(key_type="EC")[0]
    )

    payload = {"sub": "sub", "aud": BOB}
    _msg = alice.create_holder_message(
        payload=payload,
        jws_headers={"typ": "example+sd-jwt"}
    )

    # Holder
    bob = Holder(key_jar=BOB_KEY_JAR, sign_alg="ES256")
    bob.parse(_msg)

    assert bob.jwt["cnf"]["jwk"] == BOB_KEY_JAR.get_signing_key(key_type="EC")[0].serialize()

    # Send to Verifier

    # List of hashes that maps to disclosures
    release = [['given_name', "John"], ["family_name", "Doe"]]
    _disclose = []
    for attr, val in release:
        for _hash, _spec in bob.disclosure_by_hash.items():
            if attr == _spec[1] and val == _spec[2]:
                _disclose.append(_hash)

    _msg = bob.create_verifier_message(_disclose, key_holder_jwt=True, aud=CHARLIE)
    assert _msg

    # Verifier
    charlie = Verifier(key_jar=CHARLIE_KEY_JAR)
    charlie.parse(_msg)
    assert charlie.payload_audience == CHARLIE  # It's for me
    assert len(charlie.disclosure_by_hash) == len(release)  # only two data items disclosed
    # Will tell the verifier that there are data on these attributes but not what they are
    assert charlie.payload['address'] == {}  #
    assert charlie.payload['nationalities'] == []
