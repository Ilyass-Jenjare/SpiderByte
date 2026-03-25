from sqlalchemy.orm import Session
from backend.api.schemas import UserCreate
from backend.api.security import get_password_hash
from backend.database import models

def get_user(db: Session, user_id: int):
    """Cherche un utilisateur par son ID (utile pour récupérer le profil via le token)"""
    return db.query(models.User).filter(models.User.user_id == user_id).first()

def get_user_by_email(db : Session , email :str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: UserCreate):
    """Inscrit un nouvel utilisateur dans la base de données PostgreSQL"""
    
    # 1. On hache le mot de passe en clair envoyé par le schéma Pydantic
    hashed_password = get_password_hash(user.password)
    
    # 2. On fabrique l'objet SQLAlchemy avec les colonnes exactes de ton modèle
    db_user = models.User(
        username=user.username,
        fullname=user.fullname,
        email=user.email,
        hash_password=hashed_password,
        disabled= False
    )
    
    # 3. On ajoute à la session, on sauvegarde, et on rafraîchit pour obtenir le user_id généré
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user