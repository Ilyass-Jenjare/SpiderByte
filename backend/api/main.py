import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi import FastAPI, HTTPException, Depends, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from celery.result import AsyncResult
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from backend.worker.celery_app import celery_instance
from backend.database.database import engine, Base, SessionLocal, get_db
from backend.database import models, crud
from backend.api import schemas, security
from backend.api.schemas import ScanRequest

# Security
# POST   /scan/light        →  token requis + lance un Light Scan
# POST   /scan/deep         →  token requis + lance un Deep Scan
# GET    /scan/status/{id}  →  token requis + vérifie ownership
# GET    /scans/history     →  token requis + filtre par user
# GET    /scans/{id}        →  token requis + vérifie ownership  
# DELETE /scans/{id}        →  token requis + vérifie ownership

# Creation des tables s'ils existent pas 
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SpiderByte API")

allowed_origins_raw = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
)
allowed_origins = [origin.strip() for origin in allowed_origins_raw.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # token comes from /login


# Routes POST

def launch_scan(request: ScanRequest,
                token: str,
                db: Session,
                scan_type: str):
    """
    Lance un scan avec un type explicite (light/deep).
    """
    # Decodage
    email = security.decode_token(token)
    current_user = crud.get_user_by_email(db, email=email)

    # Appel de la tâche unique avec .delay()
    task = celery_instance.send_task("scan_task", args=[request.target, current_user.user_id, scan_type])

    return {
        "message": f"Scan {scan_type} démarré. Le worker va exécuter les plugins configurés.",
        "task_id": task.id,
        "status_url": f"/scan/status/{task.id}",
        "scan_type": scan_type,
        "lauched_by": email,
        "user_id": current_user.user_id
    }


@app.post("/scan/light")
def start_light_scan(request: ScanRequest,
                     token: str = Depends(oauth2_scheme),
                     db: Session = Depends(get_db)):
    return launch_scan(request, token, db, "light")


@app.post("/scan/deep")
def start_deep_scan(request: ScanRequest,
                    token: str = Depends(oauth2_scheme),
                    db: Session = Depends(get_db)):
    return launch_scan(request, token, db, "deep")


# Compatibilité rétroactive : /scan continue de lancer un Deep Scan.
@app.post("/scan")
def start_scan(request: ScanRequest,
               token: str = Depends(oauth2_scheme),
               db: Session = Depends(get_db)):
    return launch_scan(request, token, db, "deep")

@app.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Inscrit un nouvel utilisateur dans la base de données"""
    
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Cet email est déjà utilisé.")
    
    return crud.create_user(db=db, user=user)

@app.post("/login")
def login(response: Response,
           form_data: OAuth2PasswordRequestForm = Depends(),
             db: Session = Depends(get_db)):
    """Vérifie les identifiants et place le JWT dans un Cookie sécurisé"""
    # Ajout de depends pour que les deux var soient pret 
    # 1. Chercher l'utilisateur par son email (Swagger utilise 'username' par défaut pour l'identifiant)
    user = crud.get_user_by_email(db, email=form_data.username)
    
    # 2. Vérifier le mot de passe
    if not user or not security.verify_password(form_data.password, user.hash_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect."
        )
        
    # 3. Créer le Token JWT
    access_token = security.create_access_token(data={"sub": user.email})
    
    # 4. Injecter le Cookie HttpOnly dans la réponse
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=False, # À passer à True avec HTTPS
        samesite="lax",
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

# Routes GET 
@app.get('/')
def read_root():
    return {"message": "Bienvenue à l'API SpiderByte v2 (Architecture Plugin)"}

# --- Route de Statut : Vérifier l'avancement ---
@app.get("/scan/status/{task_id}")
def get_scan_status(task_id: str , token:str = Depends(oauth2_scheme) , db:Session=Depends(get_db)):
    """
    Vérifie l'état de la tâche dans Redis.
    """
    # Il faut importer l'app celery pour que AsyncResult sache où chercher
    # Si tu as une erreur ici, assure-toi d'importer 'celery_instance' de ton fichier de config
    email = security.decode_token(token)
    current_user = crud.get_user_by_email(db, email=email)

    task_result = AsyncResult(task_id, app=celery_instance)
    
    response = {
        "task_id": task_id,
        "status": task_result.status, # PENDING, PROGRESS, SUCCESS, FAILURE
        "result": None
    }

    if task_result.status == 'SUCCESS':
        response["result"] = task_result.result
    
    elif task_result.status == 'FAILURE':
        # On convertit l'erreur en string pour pouvoir l'afficher en JSON
        response["error"] = str(task_result.result)
        
    elif task_result.status == 'PROGRESS':
        # Si tu utilises self.update_state() dans le worker, tu verras les infos ici
        response["info"] = task_result.info

    return response

@app.get("/scans/history")
def get_scan_history(limit: int = 10,
                      db: Session = Depends(get_db),
                        token :str =Depends(oauth2_scheme)):
    """
    Récupère l'historique des scans effectués (max 10 par défaut)
    """
    email = security.decode_token(token)
    current_user = crud.get_user_by_email(db, email)
    scans = db.query(models.ScanResult)\
              .filter(models.ScanResult.user_id == current_user.user_id)\
              .order_by(models.ScanResult.created_at.desc())\
              .limit(limit)\
              .all()
    
    return {
        "total": len(scans),
        "scans": [
            {
                "id": scan.id,
                "task_id": scan.task_id,
                "url": scan.url,
                "status": scan.status,
                "modules_count": scan.result.get("modules_count"),
                "created_at": scan.created_at.isoformat(),
                "summary": {
                    "ssl_valid": scan.result.get("results", {}).get("ssl_check", {}).get("details", {}).get("valid"),
                    "missing_headers": len(scan.result.get("results", {}).get("header_check", {}).get("details", {}).get("missing_headers", [])),
                    "vulnerabilities": scan.result.get("results", {}).get("sql_injection", {}).get("vulnerabilities_found", 0)
                }
            }
            for scan in scans
        ]
    }

@app.get("/scans/{scan_id}")
def get_scan_details(
    scan_id: int,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    email = security.decode_token(token)
    current_user = crud.get_user_by_email(db, email=email)

    scan = db.query(models.ScanResult)\
             .filter(models.ScanResult.id == scan_id)\
             .filter(models.ScanResult.user_id == current_user.user_id)\
             .first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    
    return {
        "id": scan.id,
        "task_id": scan.task_id,
        "url": scan.url,
        "status": scan.status,
        "created_at": scan.created_at.isoformat(),
        "result": scan.result
    }


# ==========================================
# ROUTES D'AUTHENTIFICATION 
# ==========================================
@app.get("/users/me")
def profil_utilisateur(token: str = Depends(oauth2_scheme)):
    """Cette route force Swagger à afficher le bouton Authorize"""
    return {"message": "Tu as accès à cette route protégée !", "ton_token": token}

# Routes DELETE
@app.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: int,
    token: str = Depends(oauth2_scheme),  # ← ajout
    db: Session = Depends(get_db)
):
    email = security.decode_token(token)
    current_user = crud.get_user_by_email(db, email=email)

    scan = db.query(models.ScanResult)\
             .filter(models.ScanResult.id == scan_id)\
             .filter(models.ScanResult.user_id == current_user.user_id)\
             .first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    
    db.delete(scan)
    db.commit()
    
    return {"message": f"Scan {scan_id} supprimé avec succès"}


