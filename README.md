# idpy-sdjwt
Python implementation of selective disclosure (draft-ietf-oauth-selective-disclosure-jwt-05)

# Example

## Sender

First create a Sender instance

    alice = Sender(
        key_jar=ALICE_KEY_JAR,
        iss=ALICE,
        sign_alg="RS256",
        lifetime=600,
        objective_disclosure=ObjectDisclosures,
        array_disclosure=ArrayDisclosures
    )

The format of object disclosure is a simple dict

    ObjectDisclosures = {
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

    ArrayDisclosures = {
        "nationalities": ["US", "DE"],
        "team": {
            "group": ['A', 'B']
        }
    }

After having created the Sender instance you can create the 
message

    payload = {"sub": "sub", "aud": BOB}
    msg = alice.create_message(payload=payload, jws_headers={"typ": "example+sd-jwt"})

The message is an SD JWT as described in section 5.11 of 
https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html

## Receiver

Create the Reciever instance

    bob = Receiver(key_jar=BOB_KEY_JAR)

and then parse the message

    bob.parse(msg)

**bob.payload** will contain the result of parsing the JWT and applying 
all the disclosures.

If you want to have a peek at the disclosures you can view them in
**bob.disclosure_by_hash**