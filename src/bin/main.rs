use credx::issuer::{Issuer, IssuerPublic};
use credx::credential::{ClaimSchema, CredentialSchema};
use ::credx::claim::{Claim, ClaimData, ClaimType, HashedClaim, RevocationClaim, NumberClaim};
use blsful::inner_types::Scalar;
use rand::thread_rng;
use indexmap::indexmap;
use std::collections::BTreeMap;
use ::credx::knox::bbs::BbsScheme;

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


fn main() {
    println!("Running revocation test...");
    test_revocation();
}
