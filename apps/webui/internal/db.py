from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from dotenv import load_dotenv
import os

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sql_app.db")
engine = create_engine(DATABASE_URL)
Session = sessionmaker(autocommit=False, autoflush=False,bind=engine)

def get_db():
  db = Session()
  try:
    yield db
  finally:
    db.close()