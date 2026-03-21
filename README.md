# AnonCreds V2 API

## Setup
```
docker build -t anoncreds-api .
 docker run -p 8000:8000 anoncreds-api
```

## Usage

### (ISSUER) Creating a credential schema

To create a credential schema, we can use a json schema as input and add claim validators using the `minimum`, `maximum`, `minLength`, `maxlength` and `enum` keys on the properties. The `type` of the property can be used to specify if it's a `Hashed`(string) or `Number`(number) claim.

#### Json Schema
```json
{
    "title": "Sample Credential",
    "description": "A sample credential",
    "properties": {
      "name": {
        "type": "string"
      }
    }
}
```

```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/schemas/credentials' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "jsonSchema": {
    "title": "Sample Credential",
    "description": "A sample credential",
    "properties": {
      "name": {
        "type": "string"
      }
    }
  },
  "options": {}
}'
```

### (ISSUER) Creating a verification method

Once the schema is created, a verification method can be generated for issuing this credential. This will add a `verificationMethod` to the issuer's DID Document with a `credentialRegistry` property, resolving to the full AnonCreds public issuer object.

```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/issuers/{ISSUER_LABEL}/credentials' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "credSchemaId": "zQmNb6UsQsMjTbE98wn2AFPVuviG4cCgEXX8WRyzYyUPhjF"
}'
```

### (VERIFIER) Creating a presentation schema

To create a presentation schema, there are 2 vp-request-2024 presentation query types defined below.

#### Signature Query
This is used for requesting `Signature`, `Commitment`, `Range` or `Encryption` statements.
```json
{
  "type": "SignatureQuery",
  // REQUIRED identifier for the signature statement proof
  "referenceId": "sample-signature-request",
  // REQUIRED verification method restriction for the source credential
  "verificationMethod": "...",
  // OPTIONAL claims to disclose in the presentation
  "disclosed": [],
  // OPTIONAL claim commitment statement request
  "commitment": [
    {
      "claimRef": "name",
      "messageGenerator": "...",
      "blinderGenerator": "...",
      // OPTIONAL range statement on the commitment, must be a number claim
      "range": { 
        "lower": 0,
        "upper": 0
      }
    }
  ],
  // OPTIONAL encryption statement request
  "encryption": [
    {
      "claimRef": "credentialId",
      "domain": "example.com",
      "encryptionKey": "..."
    }
  ]
}
```

#### Equality Query
This is used for requesting `Equality` statements from defined `Signature` statement claims.
```json
{
  "type": "EqualityQuery",
  // REQUIRED identifier for the equality statement proof
  "referenceId": "are-names-equal",
  // REQUIRED claims for the equality request
  "claims": [
    {
      // REQUIRED claim label
      "claimRef": "name",
      // REQUIRED identifier for the signature statement proof
      "signatureRef": "sample-signature-request"
    }
  ]
}
```

```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/schemas/presentations' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "query": [
    {
      "type": "SignatureQuery",
      "referenceId": "sample-signature-request",
      "verificationMethod": "..."
    }
  ]
}'
```

### (HOLDER) Requesting a credential
Holder derives a request proof from the `subjectId` value they want to bind this credential to. This value will not be revealed to the issuer but a hash (`Scalar`) will be signed. This is a blinded claim acting as the link secret.
```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/wallets/urn:uuid:76a55fec-98df-4f57-8005-62e4c887ecb7/requests' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "verificationMethod": "..."
}'
```

### (Issuer) Issuing a credential

The issuer can issue a credential by providing the `credentialSubject` as the key:value pairs for each `Hashed` and `Number` claims from the credential schema.
A `revocationId` can also be passed as the `Revocation` claim value and a `requestProof` for the blinded `Scalar` claims.

```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/issuers/{ISSUER_LABEL}/credentials/{credentialDefinitionId}/issuee' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "credentialSubject": {
    "name": "Alice"
  },
  "options": {
    "credentialId": "...",
    "revocationId": "...",
    "requestProof": "...",
    "verificationMethod": "..."
  }
}'
```

### (Holder) Storing a credential
An issued credential and a `subjectId` can be provided to unblind the credential and store it.

```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/wallets/{HOLDER_ID}/credentials' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "credential": {}
}'
```

### (Holder) Creating a presentation
To create a holder, the `subjectId` linking the credentials as well as a `challenge` and a `presentationSchemaId` can be provided.

```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/wallets/{HOLDER_ID}/presentations' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "challenge": "...",
    "presSchemaId": "..."
}'
```

### (Verifier) Verifying a presentation

```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/verifiers/presentations/verify' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "presentation": {},
  "options": {
    "challenge": "string",
    "presSchemaId": "string"
  }
}'
```

## Utilities

### Creating an encryption keypair
```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/utilities/keys' \
  -H 'accept: application/json' \
  -d ''
```

### Generating a domain proof generator
```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/utilities/generator' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "domain": "example.com"
}'
```

### Validating a verifiable encryption
Provide the `VerifiableEncryption` proof and the associated decryption key.
```bash
curl -X 'POST' \
  'https://api.anoncreds.vc/utilities/decrypt' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "proof": {},
  "options": {
    "decryptionKey": "..."
  }
}'
```