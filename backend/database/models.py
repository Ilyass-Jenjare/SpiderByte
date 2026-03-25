from sqlalchemy import Column, Integer, String, JSON, DateTime
from sqlalchemy.sql import func
from backend.database.database import Base
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean

class ScanResult(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String, unique=True, index=True) # L'ID de Celery
    user_id = Column(Integer, ForeignKey("user.user_id"))             # ← tu ajoutes ça
    owner =  relationship("User", back_populates="scans") 
    url = Column(String, index=True)
    status = Column(String)  
    result = Column(JSON)   
    created_at = Column(DateTime(timezone=True), server_default=func.now())
     

class User(Base):
    __tablename__ = "user"
    user_id = Column(Integer, index=True, primary_key=True)
    username = Column(String, index=True)
    fullname = Column(String, index=True)
    email = Column(String, index=True)
    hash_password = Column(String)
    disabled = Column(Boolean, default=False)
    scans = relationship("ScanResult", back_populates="owner")
    