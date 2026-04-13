import json
# Assure-toi que le chemin d'importation correspond à l'endroit où se trouve ton fichier
import xss_check 

def main():
    cible = "http://demo.testfire.net/search.jsp" # L'URL avec le formulaire de recherche
    print(f"Lancement du test XSS sur {cible}...")

    # On appelle ta fonction scan
    resultat = xss_check.scan(cible)

    # On affiche le résultat formaté
    print(json.dumps(resultat, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()