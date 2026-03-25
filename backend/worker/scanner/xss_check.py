import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, InvalidElementStateException

# --- MODULE 3 : SCANNER XSS ---
def scan(url): 
        
    payloads = ["<script>alert('XSS')</script>", "'\"><img src=x onerror=alert('XSS')>"]
    
    result = {
        "scan_type": "XSS_CHECK",
        "status": "success",
        "details": {
            "parameter_injection": [],
            "input_injection": [],
        }
    }

    try:        
        # Récupérer le contenu de la page web ciblé et ces inputs
        soup = BeautifulSoup(requests.get(url).text, 'html.parser')
        inputs = soup.find_all('input')

        # Initialisation du WebDriver
        options = webdriver.ChromeOptions()
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-plugins')
        options.add_argument('--disable-images')
        
        # Connexion au conteneur Selenium
        driver = webdriver.Remote(
            command_executor='http://selenium-hub:4444',
            options=options
        )

        # Ouvre la page web ciblée
        driver.get(url)
        wait = WebDriverWait(driver, 10)

        # pour chaque payload
        for payload in payloads:
            # 1er test: test paramètre d'URL
            response = requests.get(url, params={'test': payload})
            soup = BeautifulSoup(response.text, 'html.parser')

            if payload in soup.text:
                result["details"]["parameter_injection"].append(f"Test 1: Vulnérabilité potentiel détecté avec le payload: {payload}")
            else:
                result["details"]["parameter_injection"].append(f"Test 1: Aucune vulnérabilité détectée avec le payload: {payload}")

            # 2e test: tester l'injection dans les inputs via Selenium
            try:
                search_box = wait.until(EC.element_to_be_clickable((By.NAME, 'q')))
            except TimeoutException:
                elements = driver.find_elements(By.TAG_NAME, 'input')
                search_box = None
                for el in elements:
                    if el.is_displayed() and el.is_enabled():
                        search_box = el
                        break

            if not search_box:
                result["details"]["input_injection"].append(f"Test 2: Aucun input trouvé pour tester le payload: {payload}")
            else:
                try:
                    try:
                        search_box.clear()
                    except Exception:
                        pass
                    search_box.click()
                    search_box.send_keys(payload)
                    search_box.send_keys(Keys.RETURN)
                except (InvalidElementStateException, Exception):
                    try:
                        driver.execute_script("arguments[0].value = arguments[1];", search_box, payload)
                        try:
                            search_box.send_keys(Keys.RETURN)
                        except Exception:
                            pass
                    except Exception as js_e:
                        result["details"]["input_injection"].append(f"Test 2: l'injection du payload via JS ou input échouée: {js_e}")
                        continue

            try:
                alert = driver.switch_to.alert
                result["details"]["input_injection"].append(f"Test 2: Vulnérabilité XSS détectée avec le payload: {payload}")
                alert.accept()
            except:
                result["details"]["input_injection"].append(f"Test 2: Aucune vulnérabilité détectée avec le payload: {payload}")

        # Fermer le navigateur
        driver.quit()
        
    except Exception as e:
        result["status"] = "error"
        result["error_message"] = str(e)
        result["details"]["valid"] = False
        
    return result