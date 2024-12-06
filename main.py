import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI,Request,Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import os
from starlette.middleware.base import BaseHTTPMiddleware

# 认证相关
from apps.webui.routes.auth import router as auth_router
from apps.webui.models.user import Base
from apps.webui.internal.db import engine

from apps.utils.auth import get_current_user
# 创建数据库表
Base.metadata.create_all(bind=engine)
# 加载环境变量
load_dotenv()

# 设置日志
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# 创建应用生命周期管理器
@asynccontextmanager
async def lifespan(app: FastAPI):
  # 启动时的操作
  logging.info('应用启动中...')
  yield
  # 关闭时操作
  logging.info('应用关闭中...')

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
          user = get_current_user(request)
          logging.debug(f"当前用户: {user.email if user else 'None'}")
          # 将当前用户添加到请求状态中
          request.state.user = get_current_user(request)
          print(f"get_current_user:{get_current_user(request)}")
          response = await call_next(request)
          return response
        except Exception as e:
            logging.error(f"认证中间件错误: {str(e)}")
            raise


# 创建FastAPI 应用实例
app = FastAPI(
  title = "wxcoder AI",
  description = "API 服务",
  version = "0.0.1",
  lifespan = lifespan,
  docs_url="/docs", # swagger ui 路径
  redoc_url="/redoc"

)
# 添加中间件
app.add_middleware(AuthMiddleware)
# 配置CORS
app.add_middleware(
  CORSMiddleware,
  allow_origins=os.getenv("ALLOW_ORIGINS","*").split(","), # 生产环境设为为具体的域名
  allow_credentials=True,
  allow_methods=["GET", "POST", "PUT", "DELETE"],
  allow_headers=["*"]
)


#基础健康检查接口
@app.get('/health')
async def health_check():
  return {"status": "wxcoder healthy"}



# 添加认证路由
app.include_router(auth_router,prefix="/api/auth",tags=["auth"])


if __name__ == "__main__":
  import uvicorn

  uvicorn.run(
          app,
          host=os.getenv("HOST", "0.0.0.0"),
          port=int(os.getenv("PORT", 8080)),
          reload=os.getenv("DEBUG", "False").lower() == "true"  # 开发模式下启用热重载
      )
