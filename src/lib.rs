use pyo3::prelude::*;
use pyo3::PyResult;
use blsful::inner_types::*;
use blsful::*;
use std::collections::BTreeMap;
use rand::thread_rng;
use indexmap::IndexMap;
// use ::credx::indexmap::IndexMap
use ::credx::blind::{BlindCredentialBundle, BlindCredentialRequest};
use ::credx::claim::{Claim, ClaimData, HashedClaim, RevocationClaim};
use ::credx::{
    create_domain_proof_generator, generate_verifiable_encryption_keys
};
use ::credx::prelude::{PresentationCredential, MembershipRegistry, MembershipSigningKey, MembershipVerificationKey};
use ::credx::credential::CredentialSchema;
use ::credx::presentation::{Presentation, PresentationSchema, VerifiableEncryptionProof};
use ::credx::statement::Statements;
use ::credx::knox::bbs::BbsScheme;
use ::credx::issuer::{IssuerPublic, Issuer};
// mod demo;
// use demo::check_domain_commitment;

#[pyfunction]
fn new_cred_schema(cred_schema: String) -> String {
    let cred_schema: CredentialSchema = serde_json::from_str(&cred_schema).unwrap();
    format!("{}", serde_json::to_string(&cred_schema).unwrap())
}

#[pyfunction]
fn new_pres_schema(statements: String) -> String {
    let statements: Vec<Statements<BbsScheme>> = serde_json::from_str(&statements).unwrap();
    let pres_schema: PresentationSchema<BbsScheme> = PresentationSchema::new(&statements);
    format!("{}", serde_json::to_string(&pres_schema).unwrap())
}

#[pyfunction]
fn new_issuer(schema: String) -> (String, String) {
    let cred_schema: CredentialSchema = serde_json::from_str(&schema).unwrap();
    let (issuer_public, issuer_private) = Issuer::<BbsScheme>::new(&cred_schema);
    (
        format!("{}", serde_json::to_string(&issuer_public).unwrap()),
        format!("{}", serde_json::to_string(&issuer_private).unwrap())
    )
}

#[pyfunction]
fn new_cred_request(issuer_public: String, blind_claims: String) -> (String, String, String) {
    let issuer_public: IssuerPublic<BbsScheme> = serde_json::from_str(&issuer_public).unwrap();
    let blind_claims: BTreeMap<String, ClaimData> = serde_json::from_str(&blind_claims).unwrap();
    let (request, blinder): (BlindCredentialRequest<BbsScheme>, Scalar) = BlindCredentialRequest::new(&issuer_public, &blind_claims).unwrap();
    (
        format!("{}", serde_json::to_string(&blind_claims).unwrap()),
        format!("{}", serde_json::to_string(&request).unwrap()),
        format!("{}", serde_json::to_string(&blinder).unwrap())
    )
}

#[pyfunction]
fn issue_credential(issuer_private: String, claims_data: String) -> (String, String, String) {
    let mut issuer_private: Issuer<BbsScheme> = serde_json::from_str(&issuer_private).unwrap();
    let claims_data: Vec<ClaimData> = serde_json::from_str(&claims_data).unwrap();
    let credential = issuer_private.sign_credential(&claims_data).unwrap();
    let issuer_public: IssuerPublic<BbsScheme> = IssuerPublic::from(&issuer_private);

    (
        format!("{}", serde_json::to_string(&issuer_private).unwrap()),
        format!("{}", serde_json::to_string(&issuer_public).unwrap()),
        format!("{}", serde_json::to_string(&credential).unwrap())
    )
}

#[pyfunction]
fn revoke_credentials(issuer_private: String, claims: String) -> (String, String, String) {
    let mut issuer_private: Issuer<BbsScheme> = serde_json::from_str(&issuer_private).unwrap();
    let claims_vec: Vec<RevocationClaim> = serde_json::from_str(&claims).unwrap();
    println!("Inside revoke received claims: {:?}", claims);
    println!("Inside revoke, claimns_vec is {:?}", claims_vec);
    println!("ACTIVE: {:?}", issuer_private.revocation_registry.active);
    println!("ELEMENTS: {:?}", issuer_private.revocation_registry.elements);
    let revoked_credentials = issuer_private.revoke_credentials(&claims_vec).unwrap();
    println!("ACTIVE after revocation: {:?}", issuer_private.revocation_registry.active);
    println!("ELEMENTS after revocation: {:?}", issuer_private.revocation_registry.elements);    
    let issuer_public: IssuerPublic<BbsScheme> = IssuerPublic::from(&issuer_private);

    (
        format!("{}", serde_json::to_string(&issuer_private).unwrap()),
        format!("{}", serde_json::to_string(&issuer_public).unwrap()),
        format!("{}", serde_json::to_string(&revoked_credentials).unwrap())
    )
}

#[pyfunction]
fn update_revocation_handle(issuer_private: String, claim: String) -> (String, String, String) {
    let mut issuer_private: Issuer<BbsScheme> = serde_json::from_str(&issuer_private).unwrap();
    let claim: RevocationClaim = serde_json::from_str(&claim).unwrap();
    let issuer_public: IssuerPublic<BbsScheme> = IssuerPublic::from(&issuer_private);
    let new_witness = issuer_private.update_revocation_handle(claim).unwrap();

    (
        format!("{}", serde_json::to_string(&issuer_private).unwrap()),
        format!("{}", serde_json::to_string(&issuer_public).unwrap()),
        format!("{}", serde_json::to_string(&new_witness).unwrap())
    )
}

#[pyfunction]
fn issue_blind_credential(issuer_private: String, claims_data: String, cred_request: String) -> (String, String, String) {
    let mut issuer_private: Issuer<BbsScheme> = serde_json::from_str(&issuer_private).unwrap();
    let cred_request: BlindCredentialRequest<BbsScheme> = serde_json::from_str(&cred_request).unwrap();
    let claims_data: BTreeMap<String, ClaimData> = serde_json::from_str(&claims_data).unwrap();
    let blind_bundle = issuer_private.blind_sign_credential(
        &cred_request,
        &claims_data,
    ).unwrap();
    let issuer_public: IssuerPublic<BbsScheme> = IssuerPublic::from(&issuer_private);

    (
        format!("{}", serde_json::to_string(&issuer_private).unwrap()),
        format!("{}", serde_json::to_string(&issuer_public).unwrap()),
        format!("{}", serde_json::to_string(&blind_bundle).unwrap())
    )
}

#[pyfunction]
fn create_presentation(credentials: String, pres_schema: String, nonce: &[u8]) -> String {
    let pres_schema: PresentationSchema<BbsScheme> = serde_json::from_str(&pres_schema).unwrap();
    let credentials: IndexMap<String, PresentationCredential<BbsScheme>> = serde_json::from_str(&credentials).unwrap();
    let presentation: Presentation<BbsScheme> = Presentation::create(&credentials, &pres_schema, &nonce).unwrap();

    format!("{}", serde_json::to_string(&presentation).unwrap())
}

#[pyfunction]
fn verify_presentation(pres_schema: String, presentation: String, nonce: &[u8]) -> String {
    let pres_schema: PresentationSchema<BbsScheme> = serde_json::from_str(&pres_schema).unwrap();
    let presentation: Presentation<BbsScheme> = serde_json::from_str(&presentation).unwrap();
    let verification = presentation.verify(&pres_schema, &nonce).unwrap();

    format!("{}", serde_json::to_string(&verification).unwrap())
}

#[pyfunction]
fn decrypt_proof(proof: String, decryption_key: String) -> String {
    let proof: VerifiableEncryptionProof = serde_json::from_str(&proof).unwrap();
    let decryption_key: SecretKey<Bls12381G2Impl> = serde_json::from_str(&decryption_key).unwrap();
    let value = proof.decrypt(&decryption_key);
    format!("{}", serde_json::to_string(&value).unwrap())
}

#[pyfunction]
fn new_keys() -> (String, String) {
    let (verifier_domain_specific_encryption_key, verifier_domain_specific_decryption_key) =
        generate_verifiable_encryption_keys(thread_rng());
    (
        format!("{}", serde_json::to_string(&verifier_domain_specific_encryption_key).unwrap()),
        format!("{}", serde_json::to_string(&verifier_domain_specific_decryption_key).unwrap())
    )
}

#[pyfunction]
fn msg_generator() -> String {
    format!("{}", serde_json::to_string(&G1Projective::GENERATOR).unwrap())
}

#[pyfunction]
fn domain_proof_generator(domain: &[u8]) -> String {
    let generator: G1Projective = create_domain_proof_generator(domain);
    format!("{}", serde_json::to_string(&generator).unwrap())
}

#[pyfunction]
fn create_scalar() -> String {
    let scalar = Scalar::random(rand_core::OsRng);
    format!("{}", serde_json::to_string(&scalar).unwrap())
}

#[pyfunction]
fn derive_scalar(value: String) -> String {
    let value: String = serde_json::from_str(&value).unwrap();
    let value_hash: HashedClaim = HashedClaim::from(value);
    let value_scalar: Scalar = value_hash.to_scalar();
    format!("{}", serde_json::to_string(&value_scalar).unwrap())
}

#[pyfunction]
fn create_key_scalar() -> (String, String, String) {
    let (encryption_key, decryption_key) =
        generate_verifiable_encryption_keys(thread_rng());
    let encryption_key_hex: String = serde_json::to_string(&encryption_key).unwrap();
    let encryption_key_hash: HashedClaim = HashedClaim::from(encryption_key_hex);
    let encryption_key_scalar: Scalar = encryption_key_hash.to_scalar();
    (
        format!("{}", serde_json::to_string(&encryption_key_scalar).unwrap()),
        format!("{}", serde_json::to_string(&decryption_key).unwrap()),
        format!("{}", serde_json::to_string(&encryption_key).unwrap())
    )
}

#[pyfunction]
fn membership_registry() -> (String, String, String) {
    let sk = MembershipSigningKey::new(None);
    let vk = MembershipVerificationKey::from(&sk);
    let registry = MembershipRegistry::random(thread_rng());
    (
        format!("{}", serde_json::to_string(&sk).unwrap()),
        format!("{}", serde_json::to_string(&vk).unwrap()),
        format!("{}", serde_json::to_string(&registry).unwrap())
    )
}

#[pyfunction]
fn create_commitment(value: String, domain: &[u8]) -> String {

    let value: &str = serde_json::from_str(&value).unwrap();

    let value_hash: HashedClaim = HashedClaim::from(value);
    let value_scalar: Scalar = value_hash.to_scalar();
    let value_commitment: G1Projective = create_domain_proof_generator(domain) * value_scalar;

    format!("{}", serde_json::to_string(&value_commitment).unwrap())
}

#[pyfunction]
fn reveal_blind_credential(blind_bundle: String, blind_claims: String, blinder: String) -> String {
    let blinder: Scalar = serde_json::from_str(&blinder).unwrap();
    let blind_claims: BTreeMap<String, ClaimData> = serde_json::from_str(&blind_claims).unwrap();
    let blind_bundle: BlindCredentialBundle<BbsScheme> = serde_json::from_str(&blind_bundle).unwrap();

    let credential = blind_bundle.to_unblinded(&blind_claims, blinder).unwrap();

    format!("{}", serde_json::to_string(&credential).unwrap())
}

#[pymodule]
fn anoncreds_api(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(new_cred_schema, m)?)?;
    m.add_function(wrap_pyfunction!(new_pres_schema, m)?)?;
    m.add_function(wrap_pyfunction!(new_issuer, m)?)?;

    m.add_function(wrap_pyfunction!(new_cred_request, m)?)?;
    m.add_function(wrap_pyfunction!(issue_credential, m)?)?;
    m.add_function(wrap_pyfunction!(issue_blind_credential, m)?)?;
    m.add_function(wrap_pyfunction!(create_presentation, m)?)?;
    m.add_function(wrap_pyfunction!(verify_presentation, m)?)?;

    m.add_function(wrap_pyfunction!(decrypt_proof, m)?)?;
    m.add_function(wrap_pyfunction!(new_keys, m)?)?;
    m.add_function(wrap_pyfunction!(msg_generator, m)?)?;
    m.add_function(wrap_pyfunction!(domain_proof_generator, m)?)?;
    m.add_function(wrap_pyfunction!(create_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(derive_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(membership_registry, m)?)?;
    m.add_function(wrap_pyfunction!(create_commitment, m)?)?;
    // m.add_function(wrap_pyfunction!(check_domain_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(reveal_blind_credential, m)?)?;
    m.add_function(wrap_pyfunction!(create_key_scalar, m)?)?;

    m.add_function(wrap_pyfunction!(revoke_credentials, m)?)?;
    m.add_function(wrap_pyfunction!(update_revocation_handle, m)?)?;

    Ok(())
}
