from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException

# ==========================================
# CONFIGURATION DE SÉCURITÉ
# ==========================================
SECRET_KEY = "une_cle_secrete_tres_longue_et_tres_complexe_pour_spiderbyte"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Configuration de l'algorithme de hachage (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==========================================
# FONCTIONS POUR LES MOTS DE PASSE
# ==========================================
def get_password_hash(password: str) -> str:
    """Transforme un mot de passe en clair en une suite de caractères illisibles"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie si le mot de passe tapé correspond au hash de la base de données"""
    return pwd_context.verify(plain_password, hashed_password)

# ==========================================
# FONCTION POUR LE TOKEN JWT
# ==========================================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Fabrique le 'bracelet VIP' (Token JWT)"""
    to_encode = data.copy()
    
    # Calcul de la date d'expiration
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({"exp": expire})
    
    # Création et signature du token avec notre clé secrète
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
def decode_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Token invalide")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expiré ou invalide")