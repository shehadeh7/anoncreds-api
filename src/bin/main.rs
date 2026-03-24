use credx::issuer::{Issuer, IssuerPublic};
use credx::credential::{ClaimSchema, CredentialSchema};
use ::credx::claim::{Claim, ClaimData, ClaimType, HashedClaim, RevocationClaim, NumberClaim};
use blsful::inner_types::Scalar;
use rand::thread_rng;
use indexmap::indexmap;
use std::collections::BTreeMap;
use ::credx::knox::bbs::BbsScheme;
use credx::presentation::{PresentationSchema, Presentation, PresentationCredential};
use credx::statement::{SignatureStatement, Statements, RevocationStatement};
use maplit::btreeset;
use indexmap::IndexMap;

pub fn test_revocation() {
    // -----------------------
    // 1. Schema and issuer
    // -----------------------
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "credentialId".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];
    let cred_schema = CredentialSchema::new(Some("TestCred"), Some("A test credential"), &[], &schema_claims).unwrap();

    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);

    // -----------------------
    // 2. Issue credential
    // -----------------------
    let rev_id = "86f57cd8-91ff-4cce-8592-4554a1bf6f41".to_string();
    let credential = issuer.sign_credential(&[
        RevocationClaim::from(rev_id.clone()).into(),
        HashedClaim::from("Alice").into(),
        NumberClaim::from(25).into(),
    ]).unwrap();

    println!("Issued credential: {:?}", credential);

    // -----------------------
    // 3. Revoke credential
    // -----------------------
    let rev_claim = RevocationClaim::from(rev_id.clone());
    println!("rev_claim is {:?}", rev_claim);
    let revoked = issuer.revoke_credentials(&[rev_claim.clone()]).unwrap();

    println!("Revoked credential: {:?}", revoked);

    // -----------------------
    // 4. Try revoking same credential again (should fail)
    // -----------------------
    let result = issuer.revoke_credentials(&[rev_claim.clone()]);
    match result {
        Ok(_) => println!("ERROR: Double revocation succeeded unexpectedly!"),
        Err(e) => println!("Double revocation correctly failed: {:?}", e),
    }

    // -----------------------
    // 5. Update witness for a new credential
    // -----------------------
    let rev_id2 = "rev-2".to_string();
    let credential2 = issuer.sign_credential(&[
        RevocationClaim::from(rev_id2.clone()).into(),
        HashedClaim::from("Bob").into(),
        NumberClaim::from(30).into(),
    ]).unwrap();

    let new_witness = issuer.update_revocation_handle(RevocationClaim::from(rev_id2.clone())).unwrap();
    println!("New witness for second credential: {:?}", new_witness);
}

pub fn test_revocation_full_flow() {
    // -----------------------
    // 1. Schema + issuer
    // -----------------------
    let schema_claims = [
        ClaimSchema {
            claim_type: ClaimType::Revocation,
            label: "credentialId".to_string(),
            print_friendly: false,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Hashed,
            label: "name".to_string(),
            print_friendly: true,
            validators: vec![],
        },
        ClaimSchema {
            claim_type: ClaimType::Number,
            label: "age".to_string(),
            print_friendly: true,
            validators: vec![],
        },
    ];

    let cred_schema = CredentialSchema::new(
        Some("TestCred"),
        Some("A test credential"),
        &[],
        &schema_claims,
    ).unwrap();

    let (issuer_public, mut issuer) = Issuer::<BbsScheme>::new(&cred_schema);

    // -----------------------
    // 2. Issue 2 credentials
    // -----------------------
    let rev_id1 = "rev-1".to_string();
    let rev_id2 = "rev-2".to_string();

    let cred1 = issuer.sign_credential(&[
        RevocationClaim::from(rev_id1.clone()).into(),
        HashedClaim::from("Alice").into(),
        NumberClaim::from(25u64).into(),
    ]).unwrap();

    let cred2 = issuer.sign_credential(&[
        RevocationClaim::from(rev_id2.clone()).into(),
        HashedClaim::from("Bob").into(),
        NumberClaim::from(30u64).into(),
    ]).unwrap();

    // -----------------------
    // 3. Build presentation schema from a SignatureStatement
    //    (this is what the compiler tells us to use: PresentationSchema::new)
    // -----------------------
    let sig_statement = SignatureStatement {
        issuer: issuer_public.clone(),
        id: "cred".to_string(),
        disclosed: btreeset! {},
    };
    let rev_statement = RevocationStatement {
        id: "rev".to_string(),
        reference_id: sig_statement.id.clone(),
        accumulator: issuer_public.revocation_registry.clone(),
        verification_key: issuer_public.revocation_verifying_key,
        claim: 0, // index of revocation claim
    };
    let pres_schema = PresentationSchema::new(&[
        Statements::Signature(Box::new(sig_statement)),
        Statements::Revocation(Box::new(rev_statement)),
    ]);

    let nonce = b"test-nonce-1234567890123456789012"; // must be 32 bytes for BBS

    // -----------------------
    // Helper: convert credential to IndexMap
    // -----------------------
    let make_cred_map = |bundle: &credx::credential::CredentialBundle<BbsScheme>| {
        let mut map: IndexMap<String, PresentationCredential<BbsScheme>> = IndexMap::new();
        map.insert(
            "cred".to_string(),
            PresentationCredential::from(bundle.credential.clone()),
        );
        map
    };

    // -----------------------
    // 4. Both credentials verify ✅
    // -----------------------
    let cred1_map = make_cred_map(&cred1);
    let cred2_map = make_cred_map(&cred2);

    let pres1 = Presentation::create(&cred1_map, &pres_schema, nonce).unwrap();
    let pres2 = Presentation::create(&cred2_map, &pres_schema, nonce).unwrap();

    assert!(pres1.verify(&pres_schema, nonce).is_ok(), "cred1 should verify");
    assert!(pres2.verify(&pres_schema, nonce).is_ok(), "cred2 should verify");
    println!("✅ Both credentials valid before revocation");

    // -----------------------
    // 5. Revoke cred1
    // -----------------------
    issuer.revoke_credentials(&[RevocationClaim::from(rev_id1.clone())]).unwrap();
    println!("🚫 Revoked cred1");

    // -----------------------
    // Derive fresh issuer_public AFTER revocation (simulates verifier fetching current accumulator)
    // -----------------------
    let updated_issuer_public = IssuerPublic::from(&issuer);

    let sig_statement_post = SignatureStatement {
        issuer: updated_issuer_public.clone(),
        id: "cred".to_string(),
        disclosed: btreeset! {},
    };
    let rev_statement_post = RevocationStatement {
        id: "rev".to_string(),
        reference_id: sig_statement_post.id.clone(),
        accumulator: updated_issuer_public.revocation_registry, // ← new accumulator
        verification_key: updated_issuer_public.revocation_verifying_key,
        claim: 0,
    };
    let pres_schema_post = PresentationSchema::new(&[
        Statements::Signature(Box::new(sig_statement_post)),
        Statements::Revocation(Box::new(rev_statement_post)),
    ]);

    // -----------------------
    // 6. Both fail with stale witnesses against NEW accumulator ❌
    // -----------------------
    let pres1_invalid = match Presentation::create(&cred1_map, &pres_schema_post, nonce) {
        Err(_) => true,
        Ok(p) => p.verify(&pres_schema_post, nonce).is_err(),
    };
    let pres2_invalid = match Presentation::create(&cred2_map, &pres_schema_post, nonce) {
        Err(_) => true,
        Ok(p) => p.verify(&pres_schema_post, nonce).is_err(),
    };

    assert!(pres1_invalid, "cred1 should be invalid after revocation");
    assert!(pres2_invalid, "cred2 should be invalid due to stale witness");
    println!("❌ Both credentials invalid after revocation (stale witnesses)");

    // -----------------------
    // 7. Update witness for cred2 (not revoked)
    // -----------------------
    let updated_witness = issuer
        .update_revocation_handle(RevocationClaim::from(rev_id2.clone()))
        .unwrap();

    let mut cred2_updated = cred2.clone();
    cred2_updated.credential.revocation_handle = updated_witness;

    // -----------------------
    // 8. cred2 verifies again ✅ against new schema, cred1 stays broken ❌
    // -----------------------
    let cred2_updated_map = make_cred_map(&cred2_updated);
    let pres2_fixed = Presentation::create(&cred2_updated_map, &pres_schema_post, nonce).unwrap();
    assert!(pres2_fixed.verify(&pres_schema_post, nonce).is_ok(), "cred2 should verify after witness update");
    println!("✅ Non-revoked credential works again after witness update");

    let pres1_still_bad = Presentation::create(&cred1_map, &pres_schema_post, nonce);
    let pres1_still_invalid = pres1_still_bad.is_err()
        || pres1_still_bad.unwrap().verify(&pres_schema_post, nonce).is_err();
    assert!(pres1_still_invalid, "cred1 should remain invalid");
    println!("❌ Revoked credential remains invalid");
}


fn main() {
    println!("Running revocation test...");
    test_revocation();
    println!("Running full revocation flow...");
    test_revocation_full_flow();
}
