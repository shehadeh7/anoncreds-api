from config import Config
from app.plugins.askar import AskarStorage
from app.utils import zalgo_id
import requests
import uuid
import json


class AnonCredsApi:
    def __init__(self):
        self.endpoint = Config.ANONCREDS_API

    async def provision(self):
        askar = AskarStorage()
        await askar.provision(recreate=True)
        if await askar.fetch("demo", "default"):
            return

        with open("app/static/demo/holder.json", "r") as f:
            holder = json.loads(f.read())
            
        holder_id = holder.get("subjectId")
        self.clear_wallet(holder_id)

        with open("app/static/demo/credentials/credit-card.json", "r") as f:
            cc_demo = json.loads(f.read())
            
        cc_issuer_label = cc_demo.get("issuer").get("label")
        self.clear_issuer(cc_issuer_label)

        # Create commitments
        cc_commitments = self.create_commitments(
            cc_demo.get("registry"), cc_demo.get("issuer").get("domain")
        )

        # Create Schema
        cc_schema_id = self.create_cred_schema(cc_demo.get("schema")).get("credentialSchemaId")
        cc_issuer = self.setup_issuer(cc_issuer_label, cc_schema_id)
        cc_verification_method = cc_issuer.get("verificationMethod").get('id')
        
        cc_cred_subject = cc_demo.get("credential").get("credentialSubject")
        cc_request_proof = self.request_credential(
            holder_id, cc_verification_method
        ).get("requestProof")
        cc_credential = self.issue_credential(
            issuer_label=cc_demo.get('issuer').get('label'),
            cred_subject=cc_cred_subject,
            request_proof=cc_request_proof,
            verification_method=cc_verification_method,
        ).get('credential')
        self.store_credential(holder_id, cc_credential, cc_verification_method)

        with open("app/static/demo/credentials/rebates-card.json", "r") as f:
            rc_demo = json.loads(f.read())
            
        rc_issuer_label = rc_demo.get("issuer").get("label")
        self.clear_issuer(cc_issuer_label)

        rc_schema_id = self.create_cred_schema(rc_demo.get("schema")).get("credentialSchemaId")
        rc_issuer = self.setup_issuer(rc_issuer_label, rc_schema_id)
        rc_verification_method = rc_issuer.get("verificationMethod").get('id')
        
        rc_cred_subject = rc_demo.get("credential").get("credentialSubject")
        rc_cred_subject["clientNo"] = zalgo_id(64)
        rc_request_proof = self.request_credential(
            holder_id, rc_verification_method
        ).get("requestProof")
        rc_credential = self.issue_credential(
            issuer_label=rc_demo.get('issuer').get('label'),
            cred_subject=rc_cred_subject,
            request_proof=rc_request_proof,
            verification_method=rc_verification_method,
        ).get('credential')
        self.store_credential(holder_id, rc_credential, rc_verification_method)

        with open("app/static/demo/presentations/shoes-purchase.json", "r") as f:
            shoes_demo = json.loads(f.read())
            
        shoes_demo_query = shoes_demo.get("query")
        shoes_demo_query[0]['verificationMethod'] = cc_verification_method
        shoes_demo_query[0]['encryption'][0]['encryptionKey'] = shoes_demo.get('verifier').get('encryptionKey')
        shoes_demo_query[1]['verificationMethod'] = rc_verification_method

        shoes_pres_schema_id = self.create_pres_schema(shoes_demo_query).get('presentationSchemaId')
        
        shoes_demo_challenge = str(uuid.uuid4())
        shoes_demo_presentation = self.create_presentation(
            holder_id, shoes_pres_schema_id, shoes_demo_challenge
        ).get("presentation")
        
        shoes_demo_verified = self.verify_presentation(
            shoes_demo_presentation, shoes_pres_schema_id, shoes_demo_challenge
        )
        shoes_demo_proofs = shoes_demo_presentation.get('proofs')
        for proof_id in shoes_demo_proofs:
            proof = shoes_demo_proofs.get(proof_id)
            if proof.get('VerifiableEncryption'):
                if proof.get('VerifiableEncryption').get('id') == 'cc-number-encryption':
                    shoes_demo_cc_encryption_proof = proof.get('VerifiableEncryption')
                    shoes_demo_decrypted_cc = self.decrypt_proof_issuer(shoes_demo_cc_encryption_proof, cc_issuer_label, cc_verification_method).get('decrypted')
     
                elif proof.get('VerifiableEncryption').get('id') == 'rebates-clientNo-encryption':
                    shoes_demo_rebates_encryption_proof = proof.get('VerifiableEncryption')
                    shoes_demo_decryption_key = shoes_demo.get('verifier').get('decryptionKey')
                    shoes_demo_decrypted_rebates = self.decrypt_proof(shoes_demo_rebates_encryption_proof, shoes_demo_decryption_key).get('decrypted')

        with open("app/static/demo/presentations/shorts-purchase.json", "r") as f:
            shorts_demo = json.loads(f.read())
            
        shorts_demo_query = shorts_demo.get("query")
        shorts_demo_query[0]['verificationMethod'] = cc_verification_method
        shorts_demo_query[0]['encryption'][0]['encryptionKey'] = shorts_demo.get('verifier').get('encryptionKey')
        shorts_demo_query[1]['verificationMethod'] = rc_verification_method

        shorts_pres_schema_id = self.create_pres_schema(shorts_demo_query).get('presentationSchemaId')

        shorts_demo_challenge = str(uuid.uuid4())
        shorts_demo_presentation = self.create_presentation(
            holder_id, shorts_pres_schema_id, shorts_demo_challenge
        ).get("presentation")
        
        shorts_demo_verified = self.verify_presentation(
            shorts_demo_presentation, shorts_pres_schema_id, shorts_demo_challenge
        )
        shorts_demo_proofs = shorts_demo_presentation.get('proofs')
        for proof_id in shorts_demo_proofs:
            proof = shorts_demo_proofs.get(proof_id)
            if proof.get('VerifiableEncryption'):
                if proof.get('VerifiableEncryption').get('id') == 'cc-number-encryption':
                    shorts_demo_cc_encryption_proof = proof.get('VerifiableEncryption')
                    shorts_demo_decrypted_cc = self.decrypt_proof_issuer(shorts_demo_cc_encryption_proof, cc_issuer_label, cc_verification_method).get('decrypted')
     
                elif proof.get('VerifiableEncryption').get('id') == 'rebates-clientNo-encryption':
                    shorts_demo_rebates_encryption_proof = proof.get('VerifiableEncryption')
                    shorts_demo_decryption_key = shorts_demo.get('verifier').get('decryptionKey')
                    shorts_demo_decrypted_rebates = self.decrypt_proof(shorts_demo_rebates_encryption_proof, shorts_demo_decryption_key).get('decrypted')
        

        demo = {
            "credentials": {
                "creditCard": {
                    "issuer": {
                        "name": "NeoVault",
                        "domain": "flux@neovault.bank.example",
                    },
                    "credentialSubject": cc_cred_subject,
                },
                "rebatesCard": {
                    "issuer": {
                        "name": "SynergiPay Consortium",
                        "domain": "rebates@synergipay.example",
                    },
                    "credentialSubject": rc_cred_subject,
                },
            }
        }

        await askar.store("demo", "default", demo)
        await askar.store("credential", "credit-card", cc_credential)
        await askar.store("credential", "rebates-card", rc_credential)
        await askar.store("presentation", "shoes-checkout", shoes_demo_presentation)
        await askar.store("presentation", "shorts-checkout", shorts_demo_presentation)

    def create_cred_schema(self, schema):
        r = requests.post(
            f"{self.endpoint}/schemas/credentials",
            json={"jsonSchema": schema, "options": {}},
        )
        return r.json()

    def setup_issuer(self, issuer_label, schema_id):
        r = requests.post(
            f"{self.endpoint}/issuers/{issuer_label}/credentials",
            json={"credSchemaId": schema_id},
        )
        return r.json()

    def create_pres_schema(self, query):
        r = requests.post(
            f"{self.endpoint}/schemas/presentations",
            json={"query": query},
        )
        return r.json()

    def request_credential(self, subject_id, verification_method):
        r = requests.post(
            f"{self.endpoint}/wallets/{subject_id}/requests",
            json={
                "subjectId": subject_id,
                "verificationMethod": verification_method,
            },
        )
        return r.json()

    def issue_credential(
        self, issuer_label, cred_subject, verification_method, request_proof
    ):
        r = requests.post(
            f"{self.endpoint}/issuers/{issuer_label}/credentials/{verification_method.split('#')[-1]}/issue",
            json={
                "credentialSubject": cred_subject,
                "options": {
                    # "credentialId": cred_id,
                    # "revocationId": rev_id,
                    "requestProof": request_proof,
                    "verificationMethod": verification_method,
                },
            },
        )
        return r.json()

    def create_presentation(self, subject_id, pres_schema_id, challenge):
        r = requests.post(
            f"{self.endpoint}/wallets/{subject_id}/presentations",
            json={"challenge": challenge, "presSchemaId": pres_schema_id}
        )
        return r.json()

    def create_nonce(self):
        r = requests.post(
            f"{self.endpoint}/verifiers/challenge",
        )
        return r.json()

    def store_credential(self, subject_id, credential, verification_method):
        r = requests.post(
            f"{self.endpoint}/wallets/{subject_id}/credentials",
            json={
                'credential': credential,
                'options': {
                    'verificationMethod': verification_method
                }
            }
        )
        return r.json()

    def list_credentials(self, subject_id):
        r = requests.get(
            f"{self.endpoint}/wallets/{subject_id}"
        )
        return r.json()

    def decrypt_proof(self, proof, decryption_key):
        r = requests.post(
            f"{self.endpoint}/utilities/decrypt",
            json={"proof": proof, "options": {"decryptionKey": decryption_key}},
        )
        return r.json()

    def decrypt_proof_issuer(self, proof, issuer_label, verification_method):
        r = requests.post(
            f"{self.endpoint}/issuers/{issuer_label}/credentials/{verification_method.split('#')[-1]}/decrypt",
            json={"proof": proof},
        )
        return r.json()

    def create_commitments(self, values, domain):
        commitments = {}
        for value in values:
            r = requests.post(
                f"{self.endpoint}/utilities/commitment",
                json={"value": value, "domain": domain},
            )
            commitments[value] = r.json().get("commitment")
        return commitments

    def verify_presentation(self, presentation, pres_schema_id, challenge):
        r = requests.post(
            f"{self.endpoint}/verifiers/presentations/verify",
            json={
                "presentation": presentation,
                "options": {"challenge": challenge, "presSchemaId": pres_schema_id},
            },
        )
        return r.json()


    def clear_wallet(self, holder_id):
        requests.delete(f"{self.endpoint}/wallets/{holder_id}")
        
    def clear_issuer(self, issuer_label):
        requests.delete(f"{self.endpoint}/issuers/{issuer_label}")