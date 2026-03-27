from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.plugins import AskarStorage, AnonCredsV2
from app.models.web_requests import (
    VerifyPresentationRequest,
    MessageGeneratorRequest,
    DecryptProofRequest
)

router = APIRouter(tags=["Verifiers"])
askar = AskarStorage()
anoncreds = AnonCredsV2()

@router.post("/verifiers/presentations/verify")
async def verify_presentation(request_body: VerifyPresentationRequest):
    request_body = request_body.model_dump()
    presentation = request_body.get("presentation")
    options = request_body.get("options")

    pres_schema = await askar.fetch("presentationSchema", options.get("presSchemaId"))
    if not pres_schema:
        raise HTTPException(status_code=404, detail="No presentation schema found.")

    cred_def_id_map = {}

    for stmt_id, stmt in pres_schema.get("statements", {}).items():
        if stmt.get("Signature"):
            sig = stmt["Signature"]
            cred_def_id = sig["issuer"]["id"].split("#")[-1]
            cred_def_id_map[sig["id"]] = cred_def_id

            live_cred_def = await askar.fetch("credentialDefinition", cred_def_id)
            if not live_cred_def:
                raise HTTPException(status_code=404, detail=f"Missing cred def for {cred_def_id}")
            sig["issuer"] = live_cred_def

        if stmt.get("Revocation"):
            rev = stmt["Revocation"]
            cred_def_id = cred_def_id_map.get(rev["reference_id"])

            live_cred_def = await askar.fetch("credentialDefinition", cred_def_id)
            if not live_cred_def:
                raise HTTPException(status_code=404, detail=f"Missing cred def for {cred_def_id}")
            rev["accumulator"] = live_cred_def.get("revocation_registry")
            rev["verification_key"] = live_cred_def.get("revocation_verifying_key")

    verification = anoncreds.verify_presentation(pres_schema, presentation, options.get("challenge"))
    return JSONResponse(status_code=200, content={"verification": verification})

@router.post("/verifiers/keys")
async def create_encryption_keypair():
    encryption_key, decryption_key = anoncreds.create_keypair()

    return JSONResponse(
        status_code=200,
        content={
            "encryption_key": encryption_key,
            "decryption_key": decryption_key,
        },
    )

@router.post("/verifiers/challenge")
async def create_challenge():
    return JSONResponse(
        status_code=200,
        content={
            "nonce": anoncreds.create_nonce(),
        },
    )

@router.post("/verifiers/generator")
async def create_message_generator(request_body: MessageGeneratorRequest):
    request_body = request_body.model_dump()
    return JSONResponse(
        status_code=200,
        content={
            "domain": request_body.get("domain"),
            "generator": anoncreds.message_generator(request_body.get("domain"))
        },
    )

@router.post("/verifiers/decrypt")
async def decrypt_proof(request_body: DecryptProofRequest):
    request_body = request_body.model_dump()

    proof = request_body.get("proof")
    options = request_body.get("options")

    anoncreds = AnonCredsV2()
    decrypted_proof = anoncreds.decrypt_proof(proof, options.get("decryptionKey"))

    return JSONResponse(
        status_code=201,
        content={
            "decrypted": decrypted_proof,
        },
    )