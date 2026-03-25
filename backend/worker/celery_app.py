import os
from celery import Celery

# On récupère l'URL depuis les variables d'environnement (définies dans docker-compose)
# Si on ne trouve pas la variable, on utilise localhost par défaut (pratique pour tester sans docker)
broker_url = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
backend_url = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

celery_instance = Celery(
    "worker",
    broker=broker_url,
    backend=backend_url,
    include=['backend.worker.tasks']# pour indiquer a celery ou trouver les taches 
)

celery_instance.conf.update(
    task_serializer="json",
    accept_content=["json"], # indique qu'on n'accepte que du json
    result_serializer="json", # indique qu'on stocke les resultats en json
    timezone="UTC",  # # Indique le fuseau horaire
    enable_utc=True, # Active l'UTC pour la gestion du temps
    
)