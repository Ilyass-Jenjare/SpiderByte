# backend/worker/crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from collections import deque
import re

MAX_PAGES = 40
DELAY = 0.05

def extract_text(html):
    soup = BeautifulSoup(html, "html.parser")
    for element in soup(["script", "style", "noscript", "meta", "link"]):
        element.decompose()
    return soup.get_text(separator=" ", strip=True)

def normalize_text(text):
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

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

def crawl_site(start_url, max_pages=MAX_PAGES):
    """
    Crawle le site.
    Retourne : 
    1. Une liste de formulaires (pour SQLi)
    2. Une liste d'URLs visitées (pour Nuclei)
    """
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
    
    # On renvoie les deux informations séparément !
    return list(visited), all_forms