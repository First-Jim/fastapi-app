from typing import Optional
from fastapi import Request, HTTPException, status
from apps.webui.models.user import User
from apps.webui.internal.db import Session
from apps.utils.security import decode_token, get_token_from_cookie
import logging

def get_current_user(request: Request) -> Optional[User]:
    """获取当前用户"""
    try:
        token = get_token_from_cookie(request)
        if not token:
            logging.debug("No token found in cookie")
            return None
            
        payload = decode_token(token)
        if not payload:
            logging.debug("Invalid token")
            return None
            
        user_id = payload.get("sub")
        if not user_id:
            logging.debug("No user_id in token payload")
            return None
            
        with Session() as db:
            user = User.get_user_by_id(db, user_id)
            if not user:
                logging.debug(f"No user found for id {user_id}")
            return user
    except Exception as e:
        logging.error(f"获取当前用户错误: {str(e)}")
        return None

def get_verified_user(request: Request):
    """获取已验证的用户（用于需要登录的接口）"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user

def get_admin_user(request: Request):
    """获取管理员用户（用于需要管理员权限的接口）"""
    user = get_verified_user(request)
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough privileges"
        )
    return user