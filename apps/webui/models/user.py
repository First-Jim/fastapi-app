from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Column, Integer,Index, String, DateTime, Boolean
from sqlalchemy.orm import DeclarativeBase
from pydantic import BaseModel

class Base(DeclarativeBase):
    pass

class User(Base):
  __tablename__ = 'users'

  id = Column(Integer, primary_key=True)
  email = Column(String,unique=True)
  name = Column(String)
  hashed_password = Column(String)
  role = Column(String,default="user") # admin/user
  is_active = Column(Boolean,default=True)
  create_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
  update_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

  # 创建索引
  __table_args__ = (
    Index('ix_user_id','id'),
    Index('ix_users_email','email')
  )
  @classmethod
  def get_user_by_email(cls,db_session,email: str):
    return db_session.query(cls).filter(cls.email == email).first()
  
  @classmethod
  def get_user_by_id(cls,db_session,id: str):
    return db_session.query(cls).filter(cls.id == id).first()

#Pydantic 模型用于请求和响应
class UserCreate(BaseModel):
  email: str
  password: str
  name: Optional[str] = None

class UserLogin(BaseModel):
  email: str
  password: str

class LDAPLogin(BaseModel):
  username: str
  password: str


class UserResponse(BaseModel):
  id: int
  email: str
  name: Optional[str]
  role: str
  is_active: bool = True
  create_at: datetime = datetime.now()

  class Config:
    from_attributes = True # 允许从ORM 模型创建
    





