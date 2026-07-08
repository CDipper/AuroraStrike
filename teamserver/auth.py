"""
AURORA C2 - Operator authentication dependency.
"""
from fastapi import HTTPException, Request

import config
from crypto import verify_token


async def require_op(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")

    token = auth[7:]
    user = verify_token(token, config.JWT_SECRET, config.JWT_ALGO)
    if not user:
        raise HTTPException(401, "Invalid token")
    return user
