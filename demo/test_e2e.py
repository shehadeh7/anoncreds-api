"""
End-to-end test mirroring test_revocation_full_flow in Rust.

Flow:
  1. Create credential schema
  2. Setup issuer (credential definition)
  3. Create presentation schema
  4. Issue 2 credentials (Alice + Bob)
  5. Both credentials verify ✅
  6. Revoke Alice's credential
  7. Both fail against new accumulator (stale witnesses) ❌
  8. Bob updates his revocation witness
  9. Bob verifies again ✅, Alice stays broken ❌
"""

import requests
import json
import sys

BASE = "http://localhost:8000"

ISSUER_ID = "test-issuer"
HOLDER_ALICE = "alice"
HOLDER_BOB = "bob"

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

def post(path, body=None):
    r = requests.post(f"{BASE}{path}", json=body or {})
    if not r.ok:
        print(f"  ✗ POST {path} → {r.status_code}: {r.text}")
        sys.exit(1)
    return r.json()

def get(path):
    r = requests.get(f"{BASE}{path}")
    if not r.ok:
        print(f"  ✗ GET {path} → {r.status_code}: {r.text}")
        sys.exit(1)
    return r.json()

def delete(path):
    r = requests.delete(f"{BASE}{path}")
    if not r.ok:
        print(f"  ✗ DELETE {path} → {r.status_code}: {r.text}")
        sys.exit(1)
    return r.json()

def expect_fail(path, body, label):
    """POST that we expect to fail (non-2xx) or return verification=false."""
    r = requests.post(f"{BASE}{path}", json=body or {})
    if not r.ok:
        print(f"  ✓ {label} correctly rejected (HTTP {r.status_code})")
        return True
    data = r.json()
    verification = data.get("verification")
    if verification is not None and not verification:
        print(f"  ✓ {label} correctly failed verification")
        return True
    print(f"  ✗ {label} should have failed but got: {json.dumps(data, indent=2)}")
    sys.exit(1)

def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")

# ---------------------------------------------------------------
# Teardown helpers
# ---------------------------------------------------------------

def reset_wallets():
    for holder in [HOLDER_ALICE, HOLDER_BOB]:
        requests.delete(f"{BASE}/wallets/{holder}")
    requests.delete(f"{BASE}/issuers/{ISSUER_ID}")

# ---------------------------------------------------------------
# 1. Schema
# ---------------------------------------------------------------

def step_1_create_schema():
    section("1. Create credential schema")
    body = {
        "jsonSchema": {
            "title": "TestCred",
            "description": "A test credential",
            "properties": {
                "name":  {"type": "string"},
                "age":   {"type": "number"},
            }
        },
        "options": {
            "revocable": True
        }
    }
    resp = post("/schemas/credentials", body)
    schema_id = resp["credentialSchemaId"]
    print(f"  ✓ Schema created: {schema_id}")
    return schema_id

# ---------------------------------------------------------------
# 2. Issuer / credential definition
# ---------------------------------------------------------------

def step_2_setup_issuer(schema_id):
    section("2. Setup issuer (credential definition)")
    resp = post(f"/issuers/{ISSUER_ID}/credentials", {"credSchemaId": schema_id})
    cred_def_id = resp["credentialDefinitionId"]
    verification_method = resp["verificationMethod"]["id"]
    print(f"  ✓ Credential definition: {cred_def_id}")
    print(f"  ✓ Verification method:   {verification_method}")
    return cred_def_id, verification_method

# ---------------------------------------------------------------
# 3. Presentation schema
# ---------------------------------------------------------------

def step_3_create_pres_schema(verification_method):
    section("3. Create presentation schema")
    body = {
        "query": [
            {
                "type": "SignatureQuery",
                "referenceId": "cred",
                "revRefId": "cred_rev",
                "verificationMethod": verification_method,
                "disclosed": []
            }
        ]
    }
    resp = post("/schemas/presentations", body)
    pres_schema_id = resp["presentationSchemaId"]
    print(f"  ✓ Presentation schema: {pres_schema_id}")
    return pres_schema_id

# ---------------------------------------------------------------
# 4. Issue credentials (blind credential flow)
# ---------------------------------------------------------------

def _issue_blind_credential(holder_id, verification_method, subject):
    """
    Full blind credential flow for one holder:
      1. Holder requests a blind credential (generates linkSecret + blinder)
      2. Issuer issues against the request proof
      3. Holder unblinds and stores in wallet
    Returns the unblinded credential.
    """
    cred_def_id = verification_method.split("#")[-1]

    # Step 1 — holder generates credential request
    req = post(f"/wallets/{holder_id}/requests", {
        "verificationMethod": verification_method
    })
    blinder      = req["blinder"]
    blind_claims = req["blindClaims"]
    request_proof = req["requestProof"]
    print(f"    → Credential request generated for {holder_id}")

    # Step 2 — issuer issues blind credential
    resp = post(
        f"/issuers/{ISSUER_ID}/credentials/{cred_def_id}/issue",
        {
            "credentialSubject": subject,
            "options": {
                "verificationMethod": verification_method,
                "requestProof": request_proof,
            }
        }
    )
    raw_credential = resp["credential"]
    print(f"    → Blind credential issued by issuer")

    # Step 3 — holder stores (unblinds) in wallet
    post(f"/wallets/{holder_id}/credentials", {
        "credential": raw_credential,
        "options": {
            "verificationMethod": verification_method,
        }
    })
    print(f"    → Credential unblinded and stored in {holder_id}'s wallet")

    # Return the credential as stored (fetch wallet to get unblinded form)
    wallet = get(f"/wallets/{holder_id}")
    return wallet["credentials"][-1]


def step_4_issue_credentials(verification_method):
    section("4. Issue blind credentials to Alice and Bob")

    alice_cred = _issue_blind_credential(
        HOLDER_ALICE, verification_method, {"name": "Alice", "age": 25}
    )
    print(f"  ✓ Alice's credential ready (rev claim: {_rev_claim(alice_cred)})")

    bob_cred = _issue_blind_credential(
        HOLDER_BOB, verification_method, {"name": "Bob", "age": 30}
    )
    print(f"  ✓ Bob's credential ready   (rev claim: {_rev_claim(bob_cred)})")

    return alice_cred, bob_cred

def _rev_claim(cred):
    for claim in cred.get("claims", []):
        if "Revocation" in claim:
            return claim["Revocation"].get("value")
    return None

# ---------------------------------------------------------------
# 5. Both verify before revocation
# ---------------------------------------------------------------

def step_5_verify_both(pres_schema_id, label="before revocation"):
    section(f"5. Both credentials verify ✅ ({label})")
    challenge_resp = post("/verifiers/challenge")
    challenge = challenge_resp["nonce"]

    for holder in [HOLDER_ALICE, HOLDER_BOB]:
        pres = post(f"/wallets/{holder}/presentations", {
            "presSchemaId": pres_schema_id,
            "challenge": challenge
        })["presentation"]

        result = post("/verifiers/presentations/verify", {
            "presentation": pres,
            "options": {
                "presSchemaId": pres_schema_id,
                "challenge": challenge
            }
        })
        verification = result.get("verification")
        if not verification:
            print(f"  ✗ {holder} should verify but got: {result}")
            sys.exit(1)
        print(f"  ✓ {holder} verified successfully")

# ---------------------------------------------------------------
# 6. Revoke Alice
# ---------------------------------------------------------------

def step_6_revoke_alice(verification_method, alice_cred):
    section("6. Revoke Alice's credential 🚫")
    cred_def_id = verification_method.split("#")[-1]
    alice_rev_claim = _rev_claim(alice_cred)

    post(
        f"/issuers/{ISSUER_ID}/credentials/{cred_def_id}/revoke",
        {"claims": [alice_rev_claim]}
    )
    print(f"  ✓ Revoked claim: {alice_rev_claim}")

# ---------------------------------------------------------------
# 7. Both fail with stale witnesses
# ---------------------------------------------------------------

def step_7_both_fail_stale(pres_schema_id):
    section("7. Both fail with stale witnesses against new accumulator ❌")
    challenge = post("/verifiers/challenge")["nonce"]

    for holder in [HOLDER_ALICE, HOLDER_BOB]:
        # Try to create presentation — may fail at creation or at verification
        r = requests.post(f"{BASE}/wallets/{holder}/presentations", json={
            "presSchemaId": pres_schema_id,
            "challenge": challenge
        })
        if not r.ok:
            print(f"  ✓ {holder} presentation creation correctly failed (HTTP {r.status_code})")
            continue

        pres = r.json()["presentation"]
        r2 = requests.post(f"{BASE}/verifiers/presentations/verify", json={
            "presentation": pres,
            "options": {
                "presSchemaId": pres_schema_id,
                "challenge": challenge
            }
        })
        data = r2.json()
        if not r2.ok or not data.get("verification"):
            print(f"  ✓ {holder} correctly fails verification with stale witness")
        else:
            print(f"  ✗ {holder} should have failed but verified — stale accumulator not enforced!")
            sys.exit(1)

# ---------------------------------------------------------------
# 8. Bob updates witness
# ---------------------------------------------------------------

def step_8_bob_updates_witness(verification_method, bob_cred):
    section("8. Bob updates revocation witness 🔄")
    cred_def_id = verification_method.split("#")[-1]
    bob_rev_claim = _rev_claim(bob_cred)

    post(f"/wallets/{HOLDER_BOB}/revocation_update", {
        "verificationMethod": verification_method,
        "claim": bob_rev_claim
    })
    print(f"  ✓ Bob's witness updated for claim: {bob_rev_claim}")

# ---------------------------------------------------------------
# 9. Bob verifies, Alice stays broken
# ---------------------------------------------------------------

def step_9_final_state(pres_schema_id):
    section("9. Final state — Bob ✅, Alice ❌")
    challenge = post("/verifiers/challenge")["nonce"]

    # Bob should verify
    bob_pres = post(f"/wallets/{HOLDER_BOB}/presentations", {
        "presSchemaId": pres_schema_id,
        "challenge": challenge
    })["presentation"]
    bob_result = post("/verifiers/presentations/verify", {
        "presentation": bob_pres,
        "options": {"presSchemaId": pres_schema_id, "challenge": challenge}
    })
    if not bob_result.get("verification"):
        print(f"  ✗ Bob should verify after witness update but got: {bob_result}")
        sys.exit(1)
    print(f"  ✓ Bob verifies successfully after witness update")

    # Alice should fail
    r = requests.post(f"{BASE}/wallets/{HOLDER_ALICE}/presentations", json={
        "presSchemaId": pres_schema_id,
        "challenge": challenge
    })
    if not r.ok:
        print(f"  ✓ Alice's presentation creation correctly failed (revoked)")
    else:
        alice_pres = r.json()["presentation"]
        r2 = requests.post(f"{BASE}/verifiers/presentations/verify", json={
            "presentation": alice_pres,
            "options": {"presSchemaId": pres_schema_id, "challenge": challenge}
        })
        data = r2.json()
        if not r2.ok or not data.get("verification"):
            print(f"  ✓ Alice correctly fails verification (revoked)")
        else:
            print(f"  ✗ Alice should be revoked but verified!")
            sys.exit(1)

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------

if __name__ == "__main__":
    print("\n🧪 AnonCreds V2 — End-to-End Revocation Test")
    print("   Mirrors: test_revocation_full_flow (Rust)\n")

    reset_wallets()

    schema_id                    = step_1_create_schema()
    cred_def_id, verification_method = step_2_setup_issuer(schema_id)
    pres_schema_id               = step_3_create_pres_schema(verification_method)
    alice_cred, bob_cred         = step_4_issue_credentials(verification_method)
    step_5_verify_both(pres_schema_id)
    step_6_revoke_alice(verification_method, alice_cred)
    step_7_both_fail_stale(pres_schema_id)
    step_8_bob_updates_witness(verification_method, bob_cred)
    step_9_final_state(pres_schema_id)

    print(f"\n{'═'*60}")
    print("  ✅ All steps passed — full revocation flow verified")
    print(f"{'═'*60}\n")
