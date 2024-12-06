from typing import Optional, Tuple
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.utils.conv import escape_filter_chars
from dotenv import load_dotenv
import os
import logging
load_dotenv()

LDAP_SERVER_URL = os.getenv("LDAP_SERVER_URL")
LDAP_SERVER_HOST = os.getenv("LDAP_SERVER_HOST")
LDAP_SERVER_PORT = os.getenv("LDAP_SERVER_PORT")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE")
LDAP_USER_FILTER = os.getenv("LDAP_USER_FILTER")
LDAP_USER_EMAIL_ATTRIBUTE = os.getenv("LDAP_USER_EMAIL_ATTRIBUTE")
LDAP_ATTRIBUTE_FOR_USERNAME = os.getenv("LDAP_ATTRIBUTE_FOR_USERNAME")
LDAP_ADMIN_GROUP_DN = os.getenv("LDAP_ADMIN_GROUP_DN")

class LDAPAuth:
  def __init__(self) -> None:
    self.server = Server(LDAP_SERVER_HOST,int(LDAP_SERVER_PORT),get_info=ALL)
    self.admin_connection = None

  def _get_admin_connection(self) -> Optional[Connection]:
    """获取管理员链接"""
    if not self.admin_connection:
      print(LDAP_SERVER_HOST,int(LDAP_SERVER_PORT),self.server,LDAP_BIND_PASSWORD)
      try:
        self.admin_connection = Connection(
          self.server,
          LDAP_BIND_DN,
          LDAP_BIND_PASSWORD,
          auto_bind=True,
          authentication="SIMPLE",
        )
        return self.admin_connection
      except Exception as e:
        logging.error(f"LDAP admin connection failed: {e}")
        return None
    return self.admin_connection
  
  def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[dict]]:
    """验证用户凭据并返回信息"""
    admin_conn = self._get_admin_connection()
    if not admin_conn:
        logging.error("无法建立LDAP管理员连接")
        return False, None
    
    logging.info(f"LDAP管理员连接成功: {admin_conn}")
    
    search_filter = f"(&({LDAP_ATTRIBUTE_FOR_USERNAME}={escape_filter_chars(username.lower())}))"
    logging.info(f"搜索用户，过滤条件: {search_filter}")
    
    # 搜索用户
    admin_conn.search(
        LDAP_SEARCH_BASE,
        search_filter=search_filter,
        attributes=['*']  # 获取所有属性，方便调试
    )

    if not admin_conn.entries:
        logging.error("未找到匹配的用户")
        return False, None
    
    user_dn = admin_conn.entries[0].entry_dn
    logging.info(f"找到用户DN: {user_dn}")

    # 验证用户密码
    try:
        user_conn = Connection(self.server, user_dn, password, auto_bind=True)
        if not user_conn:
            logging.error("用户连接创建失败")
            return False, None
        logging.info("用户密码验证成功")
    except Exception as e:
        logging.error(f"验证用户失败: {e}")
        return False, None

    # 获取用户信息
    try:
        # 打印所有可用的属性，用于调试
        logging.debug(f"可用的用户属性: {admin_conn.entries[0].entry_attributes_as_dict}")
        
        # 使用字符串形式的属性名
        username_attr = str(LDAP_ATTRIBUTE_FOR_USERNAME)
        email_attr = str(LDAP_USER_EMAIL_ATTRIBUTE)
        
        user_info = {
            "name": str(admin_conn.entries[0][username_attr].value),
            "email": str(admin_conn.entries[0][email_attr].value)
        }
        logging.info(f"获取到用户信息: {user_info}")
    except Exception as e:
        logging.error(f"获取用户信息失败: {e}")
        logging.error(f"LDAP_ATTRIBUTE_FOR_USERNAME: {LDAP_ATTRIBUTE_FOR_USERNAME}")
        logging.error(f"LDAP_USER_EMAIL_ATTRIBUTE: {LDAP_USER_EMAIL_ATTRIBUTE}")
        return False, None

    # 检查是否是管理员
    if LDAP_ADMIN_GROUP_DN:
        admin_conn.search(
            LDAP_ADMIN_GROUP_DN,
            f"(member={user_dn})",
            SUBTREE
        )
        user_info["role"] = "admin" if admin_conn.entries else "user"
    else:
        user_info["role"] = "user"

    return True, user_info
  

  def get_user_info(self, email: str) -> Optional[dict]:
        """获取用户信息"""
        admin_conn = self._get_admin_connection()
        if not admin_conn:
            return None

        search_filter = f"(&{LDAP_USER_FILTER}({LDAP_USER_EMAIL_ATTRIBUTE}={email}))"
        admin_conn.search(
            LDAP_SEARCH_BASE,
            search_filter,
            SUBTREE,
            attributes=[LDAP_ATTRIBUTE_FOR_USERNAME, LDAP_USER_EMAIL_ATTRIBUTE]
        )

        if not admin_conn.entries:
            return None

        user_dn = admin_conn.entries[0].entry_dn
        user_info = {
            "name": admin_conn.entries[0][LDAP_ATTRIBUTE_FOR_USERNAME].value,
            "email": admin_conn.entries[0][LDAP_USER_EMAIL_ATTRIBUTE].value,
        }

        # 检查是否是管理员
        if LDAP_ADMIN_GROUP_DN:
            admin_conn.search(
                LDAP_ADMIN_GROUP_DN,
                f"(member={user_dn})",
                SUBTREE
            )
            user_info["role"] = "admin" if admin_conn.entries else "user"
        else:
            user_info["role"] = "user"

        return user_info