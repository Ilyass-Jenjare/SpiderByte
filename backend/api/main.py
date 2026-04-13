import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fastapi import FastAPI, HTTPException, Depends, status, Response, Request
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

CELERY_TO_SCAN_STATUS = {
    "PENDING": "QUEUED",
    "PROGRESS": "PROGRESS",
    "SUCCESS": "FINISHED",
    "FAILURE": "FAILURE",
    "REVOKED": "FAILURE",
}


def normalize_scan_status(raw_status: str) -> str:
    normalized = str(raw_status or "").strip().upper()
    if not normalized:
        return "QUEUED"
    return CELERY_TO_SCAN_STATUS.get(normalized, normalized)


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

    # Appel de la tâche Celery.
    task = celery_instance.send_task("scan_task", args=[request.target, current_user.user_id, scan_type])

    initial_result = {
        "target": request.target,
        "scan_type": scan_type,
        "modules_count": 0,
        "results": {}
    }

    db_scan = db.query(models.ScanResult)\
                .filter(models.ScanResult.task_id == task.id)\
                .first()
    if db_scan:
        db_scan.url = request.target
        db_scan.user_id = current_user.user_id
        db_scan.status = "QUEUED"
        db_scan.result = initial_result
    else:
        db_scan = models.ScanResult(
            task_id=task.id,
            url=request.target,
            status="QUEUED",
            result=initial_result,
            user_id=current_user.user_id
        )
        db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    return {
        "message": f"Scan {scan_type} démarré. Le worker va exécuter les plugins configurés.",
        "task_id": task.id,
        "scan_id": db_scan.id,
        "status": db_scan.status,
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
def read_root(request: Request):
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

    db_scan = db.query(models.ScanResult)\
                .filter(models.ScanResult.task_id == task_id)\
                .filter(models.ScanResult.user_id == current_user.user_id)\
                .first()
    if not db_scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")

    task_result = AsyncResult(task_id, app=celery_instance)
    normalized_status = normalize_scan_status(task_result.status)
    current_db_status = normalize_scan_status(db_scan.status)
    if normalized_status == "QUEUED" and current_db_status in {"PROGRESS", "FINISHED", "FAILURE"}:
        # Évite de "revenir en arrière" quand le backend Celery expire le résultat et renvoie PENDING.
        normalized_status = current_db_status

    response = {
        "scan_id": db_scan.id,
        "task_id": task_id,
        "status": normalized_status,
        "raw_status": task_result.status, # PENDING, PROGRESS, SUCCESS, FAILURE
        "result": None
    }

    db_scan.status = normalized_status

    if task_result.status == 'SUCCESS':
        response["result"] = task_result.result
        if isinstance(task_result.result, dict):
            db_scan.result = task_result.result
    
    elif task_result.status == 'FAILURE':
        # On convertit l'erreur en string pour pouvoir l'afficher en JSON
        response["error"] = str(task_result.result)
        db_scan.result = {
            "target": db_scan.url,
            "scan_type": db_scan.result.get("scan_type") if isinstance(db_scan.result, dict) else "unknown",
            "error": str(task_result.result)
        }
        
    elif task_result.status == 'PROGRESS':
        # Si tu utilises self.update_state() dans le worker, tu verras les infos ici
        response["info"] = task_result.info
    elif normalized_status == "FINISHED":
        response["result"] = db_scan.result if isinstance(db_scan.result, dict) else {}
    elif normalized_status == "FAILURE":
        failure_payload = db_scan.result if isinstance(db_scan.result, dict) else {}
        response["error"] = str(failure_payload.get("error", "Scan failed"))

    db.commit()

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
    
    history_payload = []
    for scan in scans:
        scan_result = scan.result if isinstance(scan.result, dict) else {}
        modules_results = scan_result.get("results", {}) if isinstance(scan_result.get("results", {}), dict) else {}
        normalized_status = normalize_scan_status(scan.status)

        if normalized_status == "FINISHED":
            summary = {
                "ssl_valid": scan_result.get("results", {}).get("ssl_check", {}).get("details", {}).get("valid"),
                "missing_headers": len(scan_result.get("results", {}).get("header_check", {}).get("details", {}).get("missing_headers", [])),
                "vulnerabilities": scan_result.get("results", {}).get("sql_injection", {}).get("vulnerabilities_found", 0)
            }
        else:
            summary = {
                "ssl_valid": None,
                "missing_headers": 0,
                "vulnerabilities": 0
            }

        history_payload.append(
            {
                "id": scan.id,
                "task_id": scan.task_id,
                "url": scan.url,
                "status": normalized_status,
                "modules_count": scan_result.get("modules_count", len(modules_results)),
                "created_at": scan.created_at.isoformat(),
                "summary": summary
            }
        )

    return {
        "total": len(scans),
        "scans": history_payload
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
        "status": normalize_scan_status(scan.status),
        "created_at": scan.created_at.isoformat(),
        "result": scan.result if isinstance(scan.result, dict) else {}
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
