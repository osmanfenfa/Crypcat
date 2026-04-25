from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class PasswordAuditRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Password to audit")


class HashIdentifyRequest(BaseModel):
    hash_str: str = Field(..., min_length=1, description="Hash string to identify")


class HashCrackRequest(BaseModel):
    hash_str: str = Field(..., description="Hash to attempt to crack")
    hash_type: str = Field(..., description="e.g. md5, sha1, sha256")
    custom_words: Optional[list[str]] = Field(default=[], description="Extra words to try before the built-in list")


class EncryptTextRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Plain text to encrypt")
    key: Optional[str] = Field(default=None, description="Fernet key (leave blank to auto-generate)")


class DecryptRequest(BaseModel):
    token: str = Field(..., description="Fernet-encrypted token")
    key: str = Field(..., description="Fernet key used during encryption")


class BruteForceRequest(BaseModel):
    hash_str: str = Field(..., description="Hash to simulate cracking")
    hash_type: str = Field(default="md5", description="Hash algorithm")
    max_length: int = Field(default=4, ge=1, le=6, description="Maximum candidate length (1-6)")
    charset: str = Field(default="lowercase", description="digits | lowercase | uppercase | alphanumeric | full")


class GeneratePasswordRequest(BaseModel):
    length: int = Field(default=16, ge=4, le=256)
    require_upper: bool = Field(default=True)
    require_lower: bool = Field(default=True)
    require_digits: bool = Field(default=True)
    require_special: bool = Field(default=True)
    exclude_ambiguous: bool = Field(default=False, description="Exclude 0, O, l, I, 1 etc.")
    custom_special: Optional[str] = Field(default=None, description="Override the default special-character pool")


class LogEntry(BaseModel):
    id: int
    action: str
    input_summary: Optional[str]
    result_summary: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}
