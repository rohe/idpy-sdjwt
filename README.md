# idpy-sdjwt
Python implementation of selective disclosure (draft-ietf-oauth-selective-disclosure-jwt-05)

# Example

## Sender

First create some keys and an Issuer instance
    
    # Key Jar with one Elliptic curve key
    ALICE_KEY_JAR = build_keyjar(
        [{"type": "EC", "crv": "P-256", "use": ["sig"]}])
    # Save the key in the keyjar under the name of the entity
    _priv_jwks = ALICE_KEY_JAR.export_jwks(private=True)
    ALICE_KEY_JAR.import_jwks(_priv_jwks, ALICE)

    # This will eventually be the holders keys 
    BOB_KEY_JAR = build_keyjar(
        [{"type": "EC", "crv": "P-256", "use": ["sig"]}])

    alice = Issuer(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="RS256",
        lifetime=600,
        objective_disclosure=SELECTIVE_ATTRIBUTE_DISCLOSURES,
        array_disclosure=SELECTIVE_ARRAY_DISCLOSURES
    )

If the issuer wants to add a holder key it can do so:

    alice.holder_key = BOB_KEY_JAR.get_signing_key(key_type="EC")[0]

The format of attribute disclosure is a simple dict

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

Similar with array disclosure

    SELECTIVE_ARRAY_DISCLOSURES = {
        "nationalities": ["US", "DE"],
        "team": {
            "group": ['A', 'B']
        }
    }

After having created the Issuer instance and configured it to your liking you 
can create the message

    payload = {"sub": "sub", "aud": BOB}
    _issuer_msg = alice.create_message(payload=payload, 
                                       jws_headers={"typ": "example+sd-jwt"})

The message is an SD JWT as described in section 5.11 of 
https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

## Holder

Create a Holder instance

    bob = Holder(key_jar=BOB_KEY_JAR, iss=HOLDER_ID)

and then parse the message

    bob.parse(_issuer_msg)

**bob.payload** will contain the result of parsing the JWT and applying 
all the disclosures.

If you want to have a peek at the disclosures you can view them in
**bob.disclosure_by_hash**

Now if the holder wants to pass a SD JWT to a verifier it will first 
select which attributes to disclose:

    release = [['given_name', "John"], ["family_name", "Doe"]]
    _disclose = []
    # Pick the hashes that corresponds to the attribute/value pairs you
    # want to release
    for attr, val in release:
        for _hash, _spec in bob.disclosure_by_hash.items():
            if attr == _spec[1] and val == _spec[2]:
                _disclose.append(_hash)

    # To add a key holder jwt and mark the verifier as the audience of the message
    _holder_msg = bob.send(_disclose, key_holder_jwt=True, aud=VERIFIER_ID)

And lastly we will bring in the Verifier
    
    CHARLIE_KEY_JAR = KeyJar()
    # Have to have Alice's (the issuers) public keys
    CHARLIE_KEY_JAR.import_jwks(_pub_jwks, ALICE)

    Charlie = Verifier(key_jar=CHARLIE_KEY_JAR)
    charlie.parse(_holder_msg)
    # verify that it is for me
    charlie.payload_audience == VERIFIER_ID