from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    token: str
    encrypted_passwords: dict
    encryption_times_seconds: dict
    token_expiration_utc: str
