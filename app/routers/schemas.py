from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.plugins import AskarStorage, AnonCredsV2
from app.models.web_requests import (
    NewCredSchema,
    NewPresSchema,
)

router = APIRouter(tags=["Schemas"])
askar = AskarStorage()
anoncreds = AnonCredsV2()

@router.post("/schemas/credentials")
async def new_credential_schema(request_body: NewCredSchema):
    request_body = request_body.model_dump()

    cred_schema = anoncreds.create_cred_schema(
        anoncreds.map_cred_schema(
            request_body.get("jsonSchema"), request_body.get("options")
        )
    )
    cred_schema_id = cred_schema.get("id")

    if not await askar.fetch("credentialSchema", cred_schema_id):
        await askar.store("credentialSchema", cred_schema_id, cred_schema)

    return JSONResponse(
        status_code=201,
        content={
            "credentialSchemaId": cred_schema_id,
        },
    )


@router.get("/schemas/credentials/{cred_schema_id}")
async def get_credential_schema(cred_schema_id: str):
    cred_schema = await askar.fetch("credentialSchema", cred_schema_id)
    if not cred_schema:
        raise HTTPException(status_code=404, detail="No credential schema found.")
    return JSONResponse(status_code=200, content=cred_schema)


@router.post("/schemas/presentations")
async def new_presentation_schema(request_body: NewPresSchema):
    request_body = request_body.model_dump()

    queries = request_body.get("query")
    statements = []

    for query in queries:

        if query.get("type") == "SignatureQuery":
            ref_id = query.get("referenceId")
            verification_method = query.get("verificationMethod")
            cred_def_id = verification_method.split("#")[-1]

            cred_def = await askar.fetch("credentialDefinition", cred_def_id)
            if not cred_def:
                raise HTTPException(status_code=404, detail="No issuer found.")

            # Signature statement
            statements.append({
                "Signature": {
                    "id": ref_id,
                    "issuer": cred_def,
                    "disclosed": query.get("disclosed", [])
                }
            })

            # Revocation statement (if supported)
            if cred_def.get("revocation_registry"):
                statements.append({
                    "Revocation": {
                        "id": query.get("revRefId") or f"{ref_id}_rev",
                        "reference_id": ref_id,
                        "accumulator": cred_def.get("revocation_registry"),
                        "verification_key": cred_def.get("revocation_verifying_key"),
                        "claim": 0
                    }
                })

        elif query.get("type") == "EqualityQuery":
            statements.append({
                "Equality": {
                    "id": query.get("referenceId"),
                    "claims": query.get("claims")
                }
            })
            
    pres_schema = anoncreds.create_pres_schema(statements)

    pres_schema_id = pres_schema.get("id")

    if not await askar.fetch("presentationSchema", pres_schema_id):
        await askar.store("presentationSchema", pres_schema_id, pres_schema)

    return JSONResponse(
        status_code=201,
        content={
            "presentationSchemaId": pres_schema_id,
        },
    )


@router.get("/schemas/presentations/{pres_schema_id}")
async def get_presentation_schema(pres_schema_id: str):
    pres_schema = await askar.fetch("presentationSchema", pres_schema_id)
    if not pres_schema:
        raise HTTPException(status_code=404, detail="No presentation schema found.")
    return JSONResponse(status_code=200, content=pres_schema)
