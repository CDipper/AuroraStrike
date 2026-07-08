"""
AURORA C2 - API request models.
"""
from typing import Optional

from pydantic import BaseModel


class LoginReq(BaseModel):
    username: str
    password: str


class TaskReq(BaseModel):
    command: str
    args: str = ""
    source: str = "console"


class ConsoleLineReq(BaseModel):
    cls: str
    text: str


class ListenerReq(BaseModel):
    name: str
    bind_host: str = "0.0.0.0"
    bind_port: int = 8443
    public_host: str = "127.0.0.1"
    public_port: int = 8443
    protocol: str = "http"


class LocalUploadChunkReq(BaseModel):
    upload_id: str
    filename: str
    offset: int
    eof: bool = False
    data_b64: str = ""


class PayloadGenReq(BaseModel):
    listener_id: str
    sleep: Optional[int] = None
    jitter: Optional[int] = None
