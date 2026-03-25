"""
Module de scan de ports Nmap
Compatible avec l'architecture backend.worker.scanner
"""

import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import traceback

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def extract_hostname(url: str) -> str:
    """
    Extrait le nom de domaine pur ou l'IP à partir d'une URL complète.
    Ex: 'https://demo.testfire.net/login.jsp' -> 'demo.testfire.net'
    """
    try:
        parsed_url = urlparse(url)
        # Si netloc est vide, l'utilisateur a peut-être entré juste 'demo.testfire.net'
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        
        # Enlever le port s'il est spécifié (ex: demo.testfire.net:8080 -> demo.testfire.net)
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        return hostname
    except Exception:
        # En cas d'URL totalement malformée, on renvoie la chaîne brute en espérant que ça passe
        return url


def run_nmap(target_host: str) -> str:
    """
    Exécute Nmap en ligne de commande et retourne le résultat en XML.
    """
    # Explication des drapeaux :
    # -T4 : Vitesse d'exécution rapide (Timing template 4)
    # -F : Fast scan (ne scanne que les 100 ports les plus communs pour aller vite)
    # -sV : Tente de détecter les versions des services (Apache, OpenSSH, etc.)
    # -Pn : Ne fait pas de ping avant de scanner (utile si le serveur bloque les pings)
    # -oX - : Demande à Nmap de sortir le résultat en format XML dans le terminal (stdout)
    command = ["nmap", "-T4", "-F", "-sV", "-Pn", "-oX", "-", target_host]
    
    try:
        # On lance le processus de manière synchrone, capture la sortie en texte (str)
        process = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=300 # Timeout de 5 minutes max
        )
        
        # Si nmap a planté (ex: mauvaise IP), on lève une exception avec son message d'erreur
        if process.returncode != 0:
            raise RuntimeError(f"Nmap a échoué: {process.stderr}")
            
        return process.stdout
        
    except subprocess.TimeoutExpired:
        raise TimeoutError("Le scan Nmap a pris trop de temps (timeout 5 min).")
    except FileNotFoundError:
        raise FileNotFoundError("L'exécutable 'nmap' est introuvable. Est-il installé dans Docker ?")


def parse_nmap_xml(xml_content: str) -> list[dict]:
    """
    Analyse le XML brut de Nmap et retourne une liste de dictionnaires des ports ouverts.
    """
    ports_ouverts = []
    
    if not xml_content:
        return ports_ouverts
        
    try:
        root = ET.fromstring(xml_content)
        
        # Le XML de Nmap liste les hôtes, puis les ports à l'intérieur
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is None:
                continue
                
            for port in ports.findall('port'):
                state = port.find('state')
                # On ne garde que les ports réellement "open" (pas les "filtered" ou "closed")
                if state is not None and state.get('state') == 'open':
                    
                    port_info = {
                        "port": int(port.get('portid', 0)),
                        "protocol": port.get('protocol', 'inconnu'),
                        "state": "open",
                        "service": "inconnu",
                        "version": "inconnu"
                    }
                    
                    # On essaie d'extraire les infos du service s'il y en a
                    service = port.find('service')
                    if service is not None:
                        port_info["service"] = service.get('name', 'inconnu')
                        
                        # Construction de la version (produit + version + extrainfo)
                        version_parts = []
                        if service.get('product'):
                            version_parts.append(service.get('product'))
                        if service.get('version'):
                            version_parts.append(service.get('version'))
                        if service.get('extrainfo'):
                            version_parts.append(f"({service.get('extrainfo')})")
                            
                        if version_parts:
                            port_info["version"] = " ".join(version_parts)
                            
                    ports_ouverts.append(port_info)
                    
    except ET.ParseError as e:
        print(f"Erreur de parsing XML Nmap: {e}")
        
    return ports_ouverts


def generate_security_warnings(ports_ouverts: list[dict]) -> list[str]:
    """
    Génère des avertissements textuels si des ports dangereux sont trouvés.
    """
    warnings = []
    ports_critiques = {
        21: "FTP (Non chiffré, risque d'interception de mots de passe)",
        22: "SSH (Risque d'attaque brute-force, désactiver l'accès root par mot de passe)",
        23: "Telnet (Totalement obsolète et non chiffré !)",
        3306: "Base de données MySQL (Ne devrait jamais être exposée sur Internet)",
        5432: "Base de données PostgreSQL (Ne devrait jamais être exposée sur Internet)",
        3389: "Bureau à distance RDP (Fort risque d'attaque ransomware)"
    }
    
    for port_info in ports_ouverts:
        port_num = port_info["port"]
        if port_num in ports_critiques:
            warnings.append(f"ALERTE : Le port {port_num} ({ports_critiques[port_num]}) est ouvert au public.")
            
    return warnings

# ============================================================================
# FONCTION PRINCIPALE POUR L'INTÉGRATION
# ============================================================================

def scan(url: str) -> dict:
    """
    Point d'entrée principal pour le module Nmap, formaté pour l'API SpiderByte.
    """
    target_host = extract_hostname(url)
    
    try:
        # Étape 1 : Scanner
        xml_result = run_nmap(target_host)
        
        # Étape 2 : Analyser
        ports = parse_nmap_xml(xml_result)
        
        # Étape 3 : Intelligence métier (Avertissements)
        warnings = generate_security_warnings(ports)
        
        summary = f"{len(ports)} port(s) ouvert(s) détecté(s) sur {target_host}."
        if warnings:
            summary += f" Attention : {len(warnings)} service(s) sensible(s) exposé(s)."
            
        # Retour formaté et unifié
        return {
            "status": "success",
            "target": target_host,
            "open_ports_count": len(ports),
            "ports": ports,
            "security_warnings": warnings,
            "summary": summary
        }
        
    except Exception as e:
        # Format d'erreur standardisé
        return {
            "status": "error",
            "target": target_host,
            "error": str(e),
            "error_type": type(e).__name__,
            "summary": f"Échec de l'exécution de Nmap : {str(e)}",
            "traceback": traceback.format_exc()
        }


# ============================================================================
# TEST STANDALONE (optionnel)
# ============================================================================

if __name__ == "__main__":
    import json
    
    # On teste sur la cible officielle et légale de Nmap
    test_url = "http://scanme.nmap.org/"
    print(f"Lancement de Nmap sur : {test_url} (Cela peut prendre 10 à 30 secondes)...\n")
    
    result = scan(test_url)
    
    print(json.dumps(result, indent=2, ensure_ascii=False))