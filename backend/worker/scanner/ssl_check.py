import ssl
import socket
import requests
import datetime
from urllib.parse import urlparse

def get_hostname(url):
    """Extrait le hostname d'une URL (ex: https://google.com -> google.com)"""
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        # Si l'utilisateur a oublié le https://
        return urlparse(f"http://{url}").netloc
    return parsed_url.netloc

# --- MODULE 1 : SCANNER SSL ---
def scan(url):
    
    # time.sleep(70)

    hostname = get_hostname(url)
    context = ssl.create_default_context()
    
    result = {
        "scan_type": "SSL_CHECK",
        "status": "SUCCESS",
        "details": {}
    }

    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert() # Certificat SSL link to the domain
                
                # Extraction des dates
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.datetime.now()).days

                result["details"] = {
                    "valid": True,
                    "issuer": dict(x[0] for x in cert['issuer'])['commonName'],
                    "subject": dict(x[0] for x in cert['subject'])['commonName'],
                    "version": ssock.version(),
                    "expires_on": not_after.strftime("%Y-%m-%d"),
                    "days_remaining": days_left,
                    "is_expired": days_left < 0
                }
                
    except Exception as e:
        result["status"] = "error"
        result["error_message"] = str(e)
        result["details"]["valid"] = False

    return result


# --- TEST DU "PUZZLE" (Main) ---
if __name__ == "__main__":
    target = input("Entre une URL à scanner (ex: google.com) : ")
    
    print(f"\n--- Lancement de SpiderByte sur {target} ---\n")
    
    # 1. Test SSL
    print(">>> Exécution du module SSL...")
    ssl_report = scan(target)
    print(ssl_report)
    
    print("\n-------------------------------------------------\n")

    # # 2. Test Headers
    # print(">>> Exécution du module Headers...")
    # headers_report = scan_headers(target)
    # print(headers_report)