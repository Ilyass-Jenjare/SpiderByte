from backend.worker.celery_app import celery_instance
import time

# Biblio pour backend 
from backend.database.database import SessionLocal  
from backend.database.models import ScanResult       

# ==========================================
# 1. IMPORTATION EXPLICITE DES MODULES
# ==========================================
# Tu importes tes fichiers ici comme des librairies normales
from backend.worker.scanner import ssl_check
from backend.worker.scanner import header_check
from backend.worker.scanner import sql_injection
from backend.worker.scanner import nuclei_scan_copy
from backend.worker.scanner import nmap_scan , xss_check

# ==========================================
# 2. LE REGISTRE 
# ==========================================
# Tu listes simplement les modules que tu veux activer
LIGHT_SCANNERS = [
    ssl_check,
    header_check,
    nmap_scan,
]
DEEP_SCANNERS = [
    ssl_check,
    header_check,
    sql_injection,
    nmap_scan,
    nuclei_scan_copy,
    xss_check
]

SCANNERS_BY_TYPE = {
    "light": LIGHT_SCANNERS,
    "deep": DEEP_SCANNERS,
}

def resolve_scan_plan(scan_type: str):
    normalized_scan_type = str(scan_type or "deep").strip().lower()
    if normalized_scan_type not in SCANNERS_BY_TYPE:
        normalized_scan_type = "deep"
    return normalized_scan_type, SCANNERS_BY_TYPE[normalized_scan_type]

@celery_instance.task(name="scan_task", bind=True)
def perform_scan(self, url: str, user_id : int, scan_type: str = "deep"):
    self.update_state(state='PROGRESS')

    selected_scan_type, selected_scanners = resolve_scan_plan(scan_type)
    
    scan_results = {}
    # 1. On transforme la liste en dictionnaire pour stocker : { "nom_du_module": temps_en_secondes }
    modules_termines = {} 
    
    total_start_time = time.time()
    scan_start_time = time.time()

    # ==========================================
    # 3. LA BOUCLE D'EXÉCUTION
    # ==========================================
    for module in selected_scanners:
        module_name = module.__name__.split('.')[-1]
        module_start_time = time.time()
        try:
            print(f"Exécution du module : {module_name}")
            
            # On appelle la fonction scan(url) du module
            if hasattr(module, 'scan'): # verifie si une fonction scan existe 
                result = module.scan(url)
                scan_results[module_name] = result
            else:
                scan_results[module_name] = {"error": "Fonction scan() manquante"}
                
        except Exception as e:
            print(f"Crash dans {module_name}: {e}")
            scan_results[module_name] = {
                "error": "Module crashed",
                "details": str(e)
            }
        module_end_time = time.time()
        temps_execution = round(module_end_time - module_start_time, 2) # On arrondit à 2 décimales
        modules_termines[module_name] = f"{temps_execution}s"
        
        temps_total = round(time.time() - scan_start_time, 2)
        self.update_state(
            state='PROGRESS', 
            meta={
                'status': f'Analyse {selected_scan_type} en cours... ({len(modules_termines)}/{len(selected_scanners)})',
                'modules_finis': modules_termines, 
                'total_a_faire': len(selected_scanners),
                'scan_type': selected_scan_type,
                'temps_total_ecoule': f"{temps_total}s"
            }
        )    

    total_duration = time.time() - total_start_time        
    heures, reste = divmod(int(total_duration), 3600)
    minutes, secondes = divmod(reste, 60)
    temps_formate = f"{heures}h {minutes}m {secondes}s"
    print(f'total time = {temps_formate}')
    
    # ==========================================
    # 4. SAUVEGARDE EN BASE DE DONNÉES
    # ==========================================
    final_report = {
        "target": url,
        "scan_type": selected_scan_type,
        "modules_count": len(scan_results),
        "total_execution_time": temps_formate,
        "results": scan_results
    }

    db = SessionLocal()
    try:
        db_scan = ScanResult(
            task_id=self.request.id,
            url=url,
            status="Finished",
            result=final_report,
            user_id=user_id
        )
        db.add(db_scan)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Erreur DB:update_state {e}")
    finally:
        db.close()

    return final_report
