from fastapi import APIRouter, Depends,HTTPException,status,Response,Request
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm 
from sqlalchemy.orm import Session
from typing import Union
import logging
from datetime import datetime
from apps.utils.ldap_auth import LDAPAuth
from apps.webui.internal.db import get_db
from apps.webui.models.user import User,UserCreate,UserResponse,UserLogin,LDAPLogin

from apps.utils.security import (
  verify_password,
  get_password_hash,
  create_access_token,
  set_auth_cookie,
  clear_auth_cookie,
  decode_token,
  
)
from apps.utils.auth import get_current_user,get_verified_user

ldap_auth = LDAPAuth()

router = APIRouter()

oauth2_schema = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user_by_cookie(token: str = Depends(oauth2_schema),db: Session = Depends(get_db)):
  
  payload = decode_token(token)

  user = User.get_user_by_id(db,payload.get("sub"))
  if not user:
    raise HTTPException(
      status_code= status.HTTP_401_UNAUTHORIZED,
      detail="User not fond"
    )
  return user

@router.post('/register',response_model=UserResponse)
async def register(user: UserCreate,response:Response,db:Session=Depends(get_db)):
  # 检查用户是否存在
  if User.get_user_by_email(db,user.email):
    raise HTTPException(
      status_code=status.HTTP_400_BAD_REQUEST,
      detail="Email already registered"
    )
  
  # 创建新用户
  db_user = User(
    email = user.email,
    name = user.name or user.email.split("@")[0],
    hashed_password = get_password_hash(user.password)
  )

  db.add(db_user)
  db.commit()
  db.refresh(db_user)

  # 创建并设置token
  token = create_access_token(data={"sub": db_user.id})
  set_auth_cookie(response, token)
  return db_user

@router.post('/login')
async def login(
    user_login: Union[UserLogin, LDAPLogin],
    response: Response,
    db: Session = Depends(get_db)
):
    user = None
    try:
        logging.debug(f"收到登录请求: {user_login}")
        
        # 检查是否为 LDAP 登录
        if isinstance(user_login, LDAPLogin):
            authenticated, ldap_user_info = ldap_auth.authenticate(
                user_login.username,
                user_login.password
            )
            if not authenticated or not ldap_user_info:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="LDAP认证失败"
                )
            
            # 使用字典访问方式获取邮箱
            user = User.get_user_by_email(db, ldap_user_info["email"])
            
            if not user:
                # 如果用户不存在，创建新用户
                user = User(
                    email=ldap_user_info["email"],
                    name=ldap_user_info["name"],
                    role=ldap_user_info.get("role", "user"),
                    hashed_password="ldap_user"  # LDAP用户不需要本地密码
                )
                db.add(user)
                db.commit()
                db.refresh(user)

        # 检查是否为邮箱登录
        elif isinstance(user_login, UserLogin):
            user = User.get_user_by_email(db, user_login.email)
            print(999,user)
            if not user or not verify_password(user_login.password, user.hashed_password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="用户名或密码错误"
                )
        print(f"登录成功，用户:{user}")
        # 创建并设置 token
        token = create_access_token(data={"sub": user.id})
        set_auth_cookie(response, token)
        return {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"登录报错:{str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="认证失败"
        )

@router.post("/logout")
async def logout(response: Response):
    clear_auth_cookie(response)
    return {"message": "Successfully logged out"}

@router.get('/current',response_model=UserResponse) # response_mode 指定了数据模型，所以返回值字段必须匹配
async def read_users_me(request: Request):
  user = get_verified_user(request)
  if not user:
    raise HTTPException(
      status_code=status.HTTP_401_UNAUTHORIZED,
      detail="Not authenticated"
    )
  return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "is_active": getattr(user, 'is_active', True),  # 如果字段不存在则使用默认值
            "create_at": getattr(user, 'create_at', datetime.now())  # 如果字段不存在则使用默认值
    }