import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, InvalidElementStateException

# --- MODULE : SCANNER XSS ---
def scan(url):

    if not url.startswith("http"):
        url = "https://" + url

    result = {
        "scan_type": "XSS_CHECK",
        "status": "success",
        "details": {
            "vulnerabilities_found": 0,
            "vulnerable_payloads": [],
            "tested_payloads": 0,
        }
    }

    payloads = [
        "<script>alert('XSS')</script>",
        "'\"><img src=x onerror=alert('XSS')>"
    ]

    result["details"]["tested_payloads"] = len(payloads)

    try:
        options = webdriver.ChromeOptions()
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-plugins')
        options.add_argument('--disable-images')

        driver = webdriver.Remote(
            command_executor='http://selenium-hub:4444',
            options=options
        )

        driver.get(url)
        wait = WebDriverWait(driver, 10)

        for payload in payloads:
            # Test 1 : injection via paramètre URL
            response = requests.get(url, params={'test': payload})
            soup = BeautifulSoup(response.text, 'html.parser')

            if payload in soup.text:
                result["details"]["vulnerable_payloads"].append({
                    "payload": payload,
                    "method": "url_parameter",
                })
                result["details"]["vulnerabilities_found"] += 1

            # Test 2 : injection via input Selenium
            try:
                search_box = wait.until(EC.element_to_be_clickable((By.NAME, 'q')))
            except TimeoutException:
                elements = driver.find_elements(By.TAG_NAME, 'input')
                search_box = None
                for el in elements:
                    if el.is_displayed() and el.is_enabled():
                        search_box = el
                        break

            if search_box:
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
                        search_box.send_keys(Keys.RETURN)
                    except Exception:
                        pass

                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                    result["details"]["vulnerable_payloads"].append({
                        "payload": payload,
                        "method": "input_injection",
                    })
                    result["details"]["vulnerabilities_found"] += 1
                except Exception:
                    pass

        driver.quit()

    except Exception as e:
        result["status"] = "error"
        result["error_message"] = str(e)

    return result


if __name__ == "__main__":
    target = input("Entrez l'URL à scanner (ex: https://example.com): ")
    print(">>> Exécution du module XSS CHECK...")
    print(scan(target))