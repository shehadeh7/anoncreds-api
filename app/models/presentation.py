import uuid
from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field, field_validator
from config import settings


class Statement(BaseModel):
    type: str = Field()


class Signature(BaseModel):
    # type: str =Field("Signature")
    id: str = Field()
    disclosed: List[str] = Field([])
    verificationMethod: str = Field(
        example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh"
    )


class Revocation(BaseModel):
    id: str = Field()
    referenceId: str = Field()  # links to Signature.id
    verificationKey: str = Field()
    accumulator: str = Field()
    claim: int = Field()  # index of revocation claim


class Range(BaseModel):
    # type: str =Field("Range")
    # commitmentIndex: int = Field()
    # signatureIndex: int = Field(0)
    # claimRef: Union[str, int] = Field()
    referenceId: str = Field(None)
    lower: int = Field(None)
    upper: int = Field(None)


class Commitment(BaseModel):
    # type: str =Field("Commitment")
    # signatureIndex: int = Field(0)
    referenceId: str = Field(None)
    claimRef: str = Field(example="name")
    messageGenerator: str = Field(
        example="b24afdfc8024352057aa8f470804834925195dd8a1f7eada04697443ba53b2932be41ba53f9af0714b2eb33b3dc81e22"
    )
    blinderGenerator: str = Field(
        example="b4053ab8abc7933b0c63bd8aa9965fc31250fabbcc471637603f2a75a35562d635b5d934848c6a5fe712aeb64d5a948d"
    )
    range: Range = Field(None)


class Encryption(BaseModel):
    # type: str =Field("Encryption")
    # signatureIndex: int = Field(0)
    referenceId: str = Field(None)
    claimRef: str = Field(example="credentialId")
    domain: str = Field(example="example.com")
    encryptionKey: str = Field(None, example=settings.TEST_VALUES.get("encryption_key"))


class Membership(BaseModel):
    # type: str =Field("Membership")
    # signatureIndex: int = Field(0)
    claimRef: str = Field()
    accumulator: str = Field()
    verificationKey: str = Field(
        example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh"
    )


class EqualityClaim(BaseModel):
    referenceId: str = Field(None)
    claimRef: str = Field(example="name")
    signatureRef: str = Field(example="signature-request-for-some-credential")


class Equality(BaseModel):
    # type: str =Field("Equality")
    claims: List[EqualityClaim] = Field()


class ProofRequest(BaseModel):
    # type: str =Field("Equality")
    label: str = Field(example="Signature request 123")
    verificationMethod: str = Field(
        example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh"
    )
    disclosed: List[str] = Field([])
    revocation: bool = Field(True)
    commitment: List[Commitment] = Field(None)
    # membership: List[Membership]= Field()
    encryption: List[Encryption] = Field(None)


class SignatureQuery(BaseModel):
    type: str = Field("SignatureQuery")
    referenceId: str = Field(example="signature-request-for-some-credential")
    revRefId: str = Field(None)
    disclosed: List[str] = Field([])
    # revocation: bool = Field(True)
    commitment: List[Commitment] = Field(None)
    encryption: List[Encryption] = Field(None)
    verificationMethod: str = Field(
        example="zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh"
    )


class EqualityQuery(BaseModel):
    type: str = Field("EqualityQuery")
    referenceId: str = Field(example="are-names-equal")
    claims: List[EqualityClaim] = Field()
