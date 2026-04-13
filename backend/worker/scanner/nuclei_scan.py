import subprocess
import json
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import time


MAX_PAGES = 15
DELAY = 0.05  # Pour pas overcharge le serveur de nuclei
def parser_html_paths(url):
    """
    Analyse une page HTML et extrait UNIQUEMENT les liens (paths) 
    appartenant au même domaine. Optimisé pour la vitesse (ignore les formulaires).
    """
    try:   
        target_domain = urlparse(url).netloc 
        # Ajout d'un timeout pour éviter que le crawler ne reste bloqué sur une page lente
        page = requests.get(url, timeout=10, allow_redirects=True)

        # Si la page n'existe pas ou bloque la requête
        if page.status_code != 200:
            return {"error": f"Code HTTP invalide: {page.status_code}"}

        # On s'assure de ne parser que du HTML (pas des images, PDF, etc.)
        content_type = page.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            return {"error": f"Contenu non HTML: {content_type}"}

        soup = BeautifulSoup(page.text, 'html.parser')

        # Extraction des liens
        links_a = soup.find_all('a')
        links = set()
        
        for link in links_a:
            href = link.attrs.get('href')
            if href:
                # On ignore les ancres et les actions spécifiques du navigateur
                if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                    continue
                    
                # On transforme les liens relatifs (ex: /contact) en liens absolus
                full_url = urljoin(url, href) 
                link_domain = urlparse(full_url).netloc
                
                # RÈGLE D'OR : On garde uniquement les liens du même domaine 
                # pour éviter que le crawler ne parte scanner tout Internet !
                if link_domain == target_domain:
                    links.add(full_url)

        # On retourne exactement ce que ton nouveau crawler attend
        return {
            "url": url,
            "links_found": list(links)
        }

    except requests.RequestException as e:
        return {"error": f"Erreur de connexion : {e}"}
        
def crawler(start_url, max_pages=MAX_PAGES):
    """Crawle le site en breadth-first search"""
    to_visit = deque([start_url])
    visited = set()
    # all_forms = []
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.popleft()
        
        if current_url in visited:
            continue
        
        visited.add(current_url)
        result = parser_html_paths(current_url)
        
        if "error" in result:
            continue
        
        # if result['forms_found']:
        #     all_forms.extend(result['forms_found'])
        
        for link in result['links_found']:
            if link not in visited:
                to_visit.append(link)
        
        time.sleep(DELAY)
    
    return  visited

def scan(url: str) -> dict:
    """
    Point d'entrée pour le scanner Nuclei.
    1. Crawle le site pour trouver des pages.
    2. Enregistre ces pages dans un fichier texte.
    3. Lance Nuclei sur ce fichier.
    4. Parse le JSON de sortie.
    """
    targets_file = f"targets_{os.getpid()}.txt"
    results_file = f"results_{os.getpid()}.json"
    
    try:
        # 1. Récupération des cibles via le crawler intégré
        urls_to_scan = crawler(url)
        if not urls_to_scan:
            urls_to_scan = [url] # Au minimum, on scanne la racine
            
        # 2. Préparation du fichier cible pour Nuclei
        with open(targets_file, "w") as f:
            for u in urls_to_scan:
                f.write(f"{u}\n")
                
        # 3. Exécution de Nuclei via subprocess
        # On utilise -disable-update-check pour éviter que Nuclei ne mette à jour 
        # ses templates à chaque scan (ce qui ralentirait énormément ton API).
        command = [
            "nuclei", 
            "-l", targets_file, 
            "-json-export", results_file,
            "-disable-update-check"
        ]
        
        # Lancement du processus (cela va bloquer jusqu'à ce que Nuclei termine)
        subprocess.run(command, capture_output=True, text=True)
        
        # 4. Lecture et parsing des résultats
        vulns_found = []
        if os.path.exists(results_file):
            with open(results_file, "r") as f:
                for line in f:
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            
                            # On extrait uniquement ce qui nous intéresse pour SpiderByte
                            vulns_found.append({
                                "template_id": vuln_data.get("template-id", "inconnu"),
                                "name": vuln_data.get("info", {}).get("name", "Vulnérabilité sans nom"),
                                "severity": vuln_data.get("info", {}).get("severity", "info").upper(),
                                "matched_at": vuln_data.get("matched-at", url),
                                "description": vuln_data.get("info", {}).get("description", "Pas de description fournie.")
                            })
                        except json.JSONDecodeError:
                            continue
                            
        # 5. Calcul des statistiques
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns_found:
            sev = v.get("severity")
            if sev in severity_counts:
                severity_counts[sev] += 1
                
        summary = f"{len(vulns_found)} problème(s) Nuclei détecté(s) sur {len(urls_to_scan)} page(s)."
                
        return {
            "status": "success",
            "target": url,
            "pages_crawled": len(urls_to_scan),
            "vulnerabilities_found": len(vulns_found),
            "severity_breakdown": severity_counts,
            "vulnerabilities": vulns_found,
            "summary": summary
        }
        
    except Exception as e:
        return {
            "status": "error",
            "target": url,
            "error": str(e),
            "summary": "Échec de l'exécution de Nuclei."
        }
        
    finally:
        # Nettoyage des fichiers temporaires pour ne pas polluer le conteneur Docker
        if os.path.exists(targets_file):
            os.remove(targets_file)
        if os.path.exists(results_file):
            os.remove(results_file)

# ============================================================================
# TEST STANDALONE
# ============================================================================
if __name__ == "__main__":
    test_url = "https://demo.testfire.net"
    print(f"Lancement de Nuclei sur : {test_url} (Cela peut prendre 1 à 2 minutes...)")
    
    result = scan(test_url)
    print(json.dumps(result, indent=2, ensure_ascii=False))