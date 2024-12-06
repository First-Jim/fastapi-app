from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError,jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Response, Request
import logging
from dotenv import load_dotenv
import os
load_dotenv()

# 密码加密上下文
pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")

# JWT 相关配置
SECRET_KEY = os.getenv("WEBUI_SECRET_KEY")
ALGORIGHT = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60*24 #24 h
WEBUI_SESSION_COOKIE_SECURE = False
WEBUI_SESSION_COOKIE_SAME_SITE = 'lax'
def verify_password(plain_password:str,hashed_password:str) -> bool:
  return pwd_context.verify(plain_password,hashed_password)


def get_password_hash(password:str) -> str:
  return pwd_context.hash(password)


def create_access_token(data: dict,expires_delta:Optional[timedelta] = None):
  to_encode = data.copy()
  if expires_delta:
    expire = datetime.now(timezone.utc) + expires_delta
  else:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
  to_encode.update({"exp": expire})
  print(f"to_encode:{to_encode}")
  #确保 “sub" 是字符串
  if "sub" in to_encode:
    to_encode["sub"] = str(to_encode["sub"])

  encoded_jwt = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORIGHT)
  logging.debug(f"Created token: {encoded_jwt}")
  return encoded_jwt

def decode_token(token: str):
  try:
    payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORIGHT])
    logging.debug(f"Decoded payload: {payload}")
    return payload
  except JWTError as e:
    logging.error(f"Token decode error: {str(e)}")
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


#=================== set_cookie 方式 ======================

def set_auth_cookie(response:Response,token):
  response.set_cookie(
    key="token",
    value=token,
    max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    httponly=True,
    secure=WEBUI_SESSION_COOKIE_SECURE,
    samesite=WEBUI_SESSION_COOKIE_SAME_SITE,
    path="/"
  )


def get_token_from_cookie(request:Request) -> Optional[str]:
  return request.cookies.get('token')

def clear_auth_cookie(response:Response):
  response.delete_cookie(
    key="token",
    path="/",
    secure=WEBUI_SESSION_COOKIE_SECURE,
    samesite=WEBUI_SESSION_COOKIE_SAME_SITE
  )
