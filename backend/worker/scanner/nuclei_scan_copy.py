import subprocess
import json
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import time
from typing import Optional


MAX_PAGES = 15
DELAY = 0.05  # Pour pas overcharger le serveur de nuclei


# ============================================================================
# CRAWLER
# ============================================================================

def fetch_page(url: str) -> Optional[requests.Response]:
    """Effectue la requête HTTP et retourne la réponse, ou None en cas d'erreur."""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        if response.status_code != 200:
            return None
        return response
    except requests.RequestException:
        return None


def is_html_response(response: requests.Response) -> bool:
    """Vérifie que la réponse est bien du HTML."""
    content_type = response.headers.get('Content-Type', '').lower()
    return 'text/html' in content_type


def extract_links_from_html(html: str, base_url: str, target_domain: str) -> set:
    """Parse le HTML et extrait les liens appartenant au même domaine."""
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    soup_links_a = soup.find_all('a', href=True)
    for tag in soup_links_a:
        href = tag['href']

        if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            continue

        full_url = urljoin(base_url, href)
        if urlparse(full_url).netloc == target_domain:
            links.add(full_url)

    return links


def get_page_links(url: str) -> list[str]:
    """
    Récupère tous les liens internes d'une page.
    Retourne une liste vide en cas d'erreur.
    """
    response = fetch_page(url)
    if response is None or not is_html_response(response):
        return []

    target_domain = urlparse(url).netloc
    return list(extract_links_from_html(response.text, url, target_domain))


def crawler(start_url: str, max_pages: int = MAX_PAGES) -> set:
    """Crawle le site en breadth-first search et retourne les URLs visitées."""
    to_visit = deque([start_url])
    visited = set()

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.popleft()

        if current_url in visited:
            continue

        visited.add(current_url)

        for link in get_page_links(current_url):
            if link not in visited:
                to_visit.append(link)

        time.sleep(DELAY)

    return visited


# ============================================================================
# NUCLEI
# ============================================================================

def write_targets_file(urls: set, filepath: str) -> None:
    """Écrit les URLs cibles dans un fichier texte, une par ligne."""
    with open(filepath, "w") as f:
        for url in urls:
            f.write(f"{url}\n")


def run_nuclei(targets_file: str, results_file: str) -> None:
    """Lance Nuclei en subprocess sur le fichier de cibles."""
    command = [
        "nuclei",
        "-l", targets_file,
        "-json-export", results_file,
        "-disable-update-check",
        "-timeout", "15",          # ← Augmenter le timeout réseau
        "-retries", "2",           # ← Réessayer 2 fois
        "-rate-limit", "50",       # ← Limiter pour éviter les blocages
        "-no-interactsh",          # ← Désactiver Interactsh (cause du blocage Docker)
        "-severity", "low,medium,high,critical,info",
        "-exclude-tags", "wordpress,sqli,dos,fuzz",  # ← AJOUTER
        "-max-host-error", "10", 
    ]
    
    # On exécute la commande
    process = subprocess.run(command, capture_output=True, text=True)
    
    # NOUVEAU : On affiche le terminal interne de Nuclei pour déboguer !
    print("\n--- 🔍 LOGS INTERNES DE NUCLEI ---")
    print(process.stderr)
    print("----------------------------------\n")

# def parse_nuclei_results(results_file: str, fallback_url: str) -> list[dict]:
#     """Lit le fichier JSON de Nuclei et retourne une liste de vulnérabilités."""
#     if not os.path.exists(results_file):
#         return []

#     vulns = []
#     seen = set()
#     severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
#     try:
#         with open(results_file, "r") as f:
#             content = f.read().strip()
            
#         if not content:
#             return []

#         # Nuclei v3.7+ exporte un grand tableau [...]
#         if content.startswith('['):
#             data_list = json.loads(content)
#             for data in data_list:
#                 # On s'assure que chaque élément est bien un dictionnaire
#                 if isinstance(data, dict):
#                     vulns.append({
#                         "template_id": data.get("template-id", "inconnu"),
#                         "name": data.get("info", {}).get("name", "Vulnérabilité sans nom"),
#                         "severity": data.get("info", {}).get("severity", "info").upper(),
#                         "matched_at": data.get("matched-at", fallback_url),
#                         "description": data.get("info", {}).get("description", "Pas de description fournie.")
#                     })
#         else:
#             # Ancienne méthode (JSON Lines) au cas où
#             for line in content.split('\n'):
#                 if not line.strip():
#                     continue
#                 data = json.loads(line)
#                 if isinstance(data, dict):
#                     vulns.append({
#                         "template_id": data.get("template-id", "inconnu"),
#                         "name": data.get("info", {}).get("name", "Vulnérabilité sans nom"),
#                         "severity": data.get("info", {}).get("severity", "info").upper(),
#                         "matched_at": data.get("matched-at", fallback_url),
#                         "description": data.get("info", {}).get("description", "Pas de description fournie.")
#                     })
                    
#     except Exception as e:
#         print(f"Erreur de parsing JSON Nuclei : {e}")

#     return vulns
def parse_nuclei_results(results_file: str, fallback_url: str) -> list[dict]:
    """Lit le fichier JSON de Nuclei et retourne une liste de vulnérabilités."""
    if not os.path.exists(results_file):
        return []

    vulns = []
    seen = set()
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    try:
        with open(results_file, "r") as f:
            content = f.read().strip()

        if not content:
            return []

        data_list = json.loads(content) if content.startswith('[') else [
            json.loads(line) for line in content.split('\n') if line.strip()
        ]

        for data in data_list:
            if not isinstance(data, dict):
                continue

            info           = data.get("info", {})
            classification = info.get("classification", {})
            if not isinstance(classification, dict):
                classification = {}

            template_id = data.get("template-id", "inconnu")
            matched_at  = data.get("matched-at", fallback_url)

            dedup_key = f"{template_id}:{matched_at}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            vulns.append({
                "template_id": template_id,
                "name":        info.get("name", "Vulnérabilité sans nom"),
                "severity":    info.get("severity", "info").upper(),
                "type":        data.get("type", ""),
                "matched_at":  matched_at,
                "description": info.get("description", "").strip(),
                "remediation": info.get("remediation", ""),
                "tags":        info.get("tags", []),
                "cve":         classification.get("cve-id", None),
                "cvss_score":  classification.get("cvss-score", None),
                "timestamp":   data.get("timestamp", ""),
            })

    except Exception as e:
        print(f"Erreur de parsing JSON Nuclei : {e}")

    vulns.sort(key=lambda x: severity_order.get(x["severity"], 5))
    return vulns

def compute_severity_breakdown(vulns: list[dict]) -> dict:
    """Calcule le nombre de vulnérabilités par niveau de sévérité."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        sev = v.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


# ============================================================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================================================

def scan(url: str) -> dict:
    """
    Lance un scan complet sur une URL :
    1. Crawle le site pour découvrir les pages.
    2. Lance Nuclei sur ces pages.
    3. Retourne un rapport structuré.
    """
    targets_file = f"targets_{os.getpid()}.txt"
    results_file = f"results_{os.getpid()}.json"

    try:
        urls_to_scan = crawler(url) or {url}

        write_targets_file(urls_to_scan, targets_file)
        run_nuclei(targets_file, results_file)

        vulns = parse_nuclei_results(results_file, fallback_url=url)
        severity_breakdown = compute_severity_breakdown(vulns)

        return {
            "status": "success",
            "target": url,
            "pages_crawled": len(urls_to_scan),
            "vulnerabilities_found": len(vulns),
            "severity_breakdown": severity_breakdown,
            "vulnerabilities": vulns,
            "summary": f"{len(vulns)} problème(s) Nuclei détecté(s) sur {len(urls_to_scan)} page(s)."
        }

    except Exception as e:
        return {
            "status": "error",
            "target": url,
            "error": str(e),
            "summary": "Échec de l'exécution de Nuclei."
        }

    finally:
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