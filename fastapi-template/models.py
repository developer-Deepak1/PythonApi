from typing import Any, Dict, Optional
from pydantic import BaseModel


class MsgPayload(BaseModel):
    msg_id: Optional[int]
    msg_name: str

class Header(BaseModel):
    apiKey: str
    x_tokey_key: str
    accept: str

class RequestBody(BaseModel):
    payload: Dict[str, Any]
    apiBaseUrl: str

class RequestPayload(BaseModel):
    header: Header
    requestBody: RequestBody

class ResponsePayload(BaseModel):
    statusCode: int
    data: Dict[str, Any]
    success: bool  
    message: str  