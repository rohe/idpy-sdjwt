import os

from cryptojwt import KeyBundle
from cryptojwt import KeyJar
from cryptojwt.jws.jws import factory
from idpysdjwt.entity import Receiver
from idpysdjwt.entity import Sender

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
# Load the opponents keys
_jwks = ALICE_KEY_JAR.export_jwks_as_json(issuer_id=ALICE)
BOB_KEY_JAR = KeyJar()
BOB_KEY_JAR.import_jwks_as_json(_jwks, ALICE)

EndUserClaims = {
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

SELDISC = {
    "nationalities": ["US", "DE"],
    "team": {
        "group": ['A', 'B']
    }
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

    kw = alice.evaluate(_msg, _part[1:-1])

    assert set(kw.keys()) == {'address', 'aud', 'cnf', 'exp', 'family_name', 'team',
                              'foo', 'given_name', 'iat', 'iss', 'nationalities', 'sub'}

    assert set(kw['nationalities']) == {"US", "DE"}


def test_sender_receiver():
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

    bob = Receiver(key_jar=BOB_KEY_JAR)
    bob.parse(_msg)

    assert set(bob.payload.keys()) == {'address', 'aud', 'cnf', 'exp', 'family_name', 'team',
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

    bob = Receiver(key_jar=BOB_KEY_JAR)
    bob.parse(msg)
    assert set(bob.payload.keys()) == {'address', 'birthdate', 'cnf', 'email', 'exp',
                                       'family_name', 'given_name', 'iat', 'iss', 'nationalities',
                                       'phone_number', 'phone_number_verified', 'sub', 'updated_at'}
    assert bob.payload['nationalities'] == ['US']
    assert bob.payload['birthdate'] == '1940-01-01'
    assert len(bob.disclosure_by_hash.keys()) == 9

def test_receiver_msg_2():
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

    bob = Receiver(key_jar=BOB_KEY_JAR)
    bob.parse(msg)
    assert set(bob.payload.keys()) == {'address', 'cnf', 'exp', 'family_name',
                                       'given_name', 'iat', 'iss', 'nationalities', 'sub'}

    assert bob.payload['family_name'] == "Doe"
    assert bob.payload['given_name'] == "John"
    assert bob.payload['address'] == {'country': 'US',
                                      'locality': 'Anytown',
                                      'region': 'Anystate',
                                      'street_address': '123 Main St'}
    assert bob.payload['nationalities'] == []

    assert len(bob.disclosure_by_hash.keys()) == 3