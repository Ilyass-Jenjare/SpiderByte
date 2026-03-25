from pydantic import BaseModel
from pydantic import Field

from typing import Optional

# --- Modèles de données ---
class ScanRequest(BaseModel):
    target: str  
    
# ==========================================
# SCHÉMAS POUR L'UTILISATEUR
# ==========================================

class UserBase(BaseModel):
    """La base commune à tous les schémas utilisateur"""
    email: str
    username: str
    fullname: str

class UserCreate(UserBase):
    """Ce que l'API exige de recevoir quand un client s'inscrit"""
    password: str

class UserResponse(UserBase):
    """Ce que l'API a le droit de renvoyer au client (PAS de mot de passe !)"""
    id: int = Field(alias="user_id")
    disabled: bool

    class Config:
        # Permet à Pydantic de lire directement les objets de la base de données (SQLAlchemy)
        from_attributes = True 

# ==========================================
# SCHÉMAS POUR L'AUTHENTIFICATION (JWT)
# ==========================================

class Token(BaseModel):
    """Le format du badge d'accès renvoyé après une connexion réussie"""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Les données que l'on va cacher à l'intérieur du Token JWT"""
    email: Optional[str] = None