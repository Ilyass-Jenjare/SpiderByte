import ssl
import socket
import requests
import datetime
from urllib.parse import urlparse

# --- MODULE 2 : SCANNER HEADERS DE SÉCURITÉ ---

def scan(url):
    # On s'assure d'avoir le schéma pour requests
    if not url.startswith("http"):
        url = "https://" + url

    result = {
        "scan_type": "HEADERS_CHECK",
        "status": "success",
        "details": {

            
            "missing_headers": [],
            "present_headers": {}
        }
    }

    # Liste des headers recommandés par l'OWASP
    security_headers_required = [
        "Strict-Transport-Security",   # HSTS force HTTPS
        "Content-Security-Policy",     # CSP n'autorise que certains script de certains domaines
        "X-Frame-Options",             # Anti-Clickjacking
        "X-Content-Type-Options",      # Anti-MIME sniffing
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    try:
        # On utilise un User-Agent pour ne pas être bloqué par certains pare-feux
        headers_agent = {'User-Agent': 'SpiderByte-Scanner/1.0'}
        response = requests.get(url, headers=headers_agent, timeout=10)
        
        server_headers = response.headers

        # Vérification des headers manquants
        for header in security_headers_required:
            if header in server_headers:
                result["details"]["present_headers"][header] = server_headers[header]
            else:
                result["details"]["missing_headers"].append(header)
        
        # Vérification si le serveur divulgue trop d'infos (ex: "Server: Apache/2.4.41")
        if "Server" in server_headers:
             result["details"]["server_leaked_info"] = server_headers["Server"]

    except requests.exceptions.RequestException as e:
        result["status"] = "error"
        result["error_message"] = str(e)

    return result


if __name__ == "__main__":
    target = input("Entrez l'URL ou le domaine à scanner (ex: example.com): ")
    
    print(">>> Exécution du module HEADERS CHECK...")
    headers_report = scan(target)
    print(headers_report)


    