# SpiderByte

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![React](https://img.shields.io/badge/react-18.2-blue)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![License](https://img.shields.io/badge/license-MIT-green.svg)

SpiderByte est une plateforme de scanning de sécurité web (DAST — Dynamic Application Security Testing) orientée Cloud-Native. Elle permet d'auditer les vulnérabilités d'applications web modernes via une interface full-stack avec authentification, gestion des résultats en temps réel et scans parallélisés.

---
##  Démo en action


https://github.com/user-attachments/assets/00f4b747-ac02-4ed7-aa89-d9080a200a8e


## Table des matières

- [Architecture](#architecture)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Lancement](#lancement)
- [Utilisation](#utilisation)
- [Endpoints API](#endpoints-api)
- [Structure du projet](#structure-du-projet)
- [Variables d'environnement](#variables-denvironnement)
- [Roadmap](#roadmap)
- [Avertissement légal](#avertissement-légal)

---

## Architecture

SpiderByte repose sur une architecture microservices entièrement conteneurisée. L'ensemble de la stack est accessible via un unique point d'entrée — `http://localhost` — grâce à Nginx qui joue le rôle de reverse proxy. Aucun port applicatif n'est exposé directement depuis l'hôte.

```
                    +-----------------------------+
                    |       NGINX  (port 80)      |
                    |       Reverse Proxy         |
                    +----+----+----+--------------+
                         |    |    |
            +------------+    |    +------------+
            |                 |                 |
     +------+------+   +------+------+   +------+------+
     |  Frontend   |   |   Backend   |   |   Flower    |
     |  React/Vite |   |   FastAPI   |   |  Celery UI  |
     |  :3000      |   |   :8000     |   |  :5555      |
     +-------------+   +------+------+   +-------------+
                              |
               +--------------+--------------+
               |                             |
        +------+------+             +--------+------+
        |    Celery   |             |     Redis     |
        |    Worker   |             |    Broker     |
        +------+------+             +---------------+
               |
        +------+------+
        |  PostgreSQL |
        |    :5432    |
        +-------------+
```

| Service      | Role                                                   | Port interne |
|--------------|--------------------------------------------------------|--------------|
| `nginx`      | Reverse proxy — seul port exposé vers l'hôte          | 80           |
| `frontend`   | Interface utilisateur React                            | 3000         |
| `backend`    | API REST FastAPI                                       | 8000         |
| `worker`     | Tâches asynchrones Celery                              | —            |
| `redis`      | Broker de messages et cache                            | 6379         |
| `postgres`   | Base de données relationnelle                          | 5432         |
| `selenium`   | Chrome autonome pour les tests dynamiques              | 4444         |
| `flower`     | Dashboard de monitoring des tâches Celery              | 5555         |

---

## Fonctionnalités

### Authentification

- Inscription et connexion par email
- Hashage des mots de passe avec bcrypt
- Sessions sécurisées via JWT (OAuth2)

### Types de scans

#### Scan léger — `POST /scan/light`

Analyse rapide, idéale pour une première évaluation :

- Vérification SSL/TLS
- Analyse des en-têtes HTTP de sécurité
- Scan de ports avec Nmap

#### Scan approfondi — `POST /scan/deep`

Audit complet orienté sécurité offensive :

- Vérification SSL/TLS
- Analyse des en-têtes HTTP de sécurité
- Détection d'injections SQL
- Scan de ports avec Nmap
- Scan de vulnérabilités avec Nuclei
- Détection de failles XSS

### Modules de scanning

| Module              | Fonction                                      |
|---------------------|-----------------------------------------------|
| `ssl_check.py`      | Vérification des certificats SSL/TLS          |
| `header_check.py`   | Analyse des en-têtes HTTP de sécurité         |
| `nmap_scan.py`      | Scan de ports et services                     |
| `sql_injection.py`  | Détection de failles d'injection SQL          |
| `xss_check.py`      | Test de vulnérabilités XSS                    |
| `nuclei_scan.py`    | Scanner de vulnérabilités avancé              |

### Workflow d'un scan

```
1. L'utilisateur soumet une URL via /scan/light ou /scan/deep
2. FastAPI valide le token JWT
3. Une tâche Celery est créée et publiée dans Redis
4. Le worker Celery récupère et exécute la tâche
5. Les modules de scan s'exécutent séquentiellement
6. Les résultats sont persistés dans PostgreSQL
7. Le frontend interroge /scan/status/{id} pour suivre l'avancement
8. Les résultats sont affichés en temps réel
```

---

## Prérequis

- [Git](https://git-scm.com/) >= 2.x
- [Docker](https://docs.docker.com/get-docker/) >= 24.x
- [Docker Compose](https://docs.docker.com/compose/install/) >= 2.x

Vérification :

```bash
git --version
docker --version
docker compose version
```

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-nom-utilisateur/SpiderByte.git
cd SpiderByte
```

### 2. Configurer les variables d'environnement

```bash
cp .env.example .env
```

Éditez `.env` selon vos besoins (voir la section [Variables d'environnement](#variables-denvironnement)).

---

## Lancement

### Démarrer la stack

```bash
docker compose up --build
```

L'application est disponible sur **`http://localhost`** une fois tous les services démarrés.

### Mode détaché (arrière-plan)

```bash
docker compose up --build -d
```

### Vérifier l'état des services

```bash
docker compose ps
```

### Consulter les logs

```bash
# Tous les services
docker compose logs -f

# Un service spécifique
docker compose logs -f backend
docker compose logs -f worker
```

### Arrêter la stack

```bash
docker compose down
```

### Reset complet (suppression des volumes)

```bash
docker compose down -v
```

---

## Utilisation

Une fois la stack démarrée, les points d'accès disponibles sont :

| URL                           | Description                              |
|-------------------------------|------------------------------------------|
| `http://localhost`            | Interface principale (Frontend React)    |
| `http://localhost/api/docs`   | Documentation Swagger de l'API           |
| `http://localhost/api/redoc`  | Documentation ReDoc de l'API             |
| `http://localhost/flower`     | Dashboard Celery (monitoring des tâches) |

### Lancer un scan via l'interface

1. Rendez-vous sur `http://localhost`
2. Créez un compte ou connectez-vous
3. Entrez l'URL cible dans le champ de saisie
4. Choisissez le type de scan (léger ou approfondi)
5. Suivez l'avancement en temps réel et consultez les résultats

### Lancer un scan via l'API

```bash
# Scan léger
curl -X POST http://localhost/api/scan/light \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Scan approfondi
curl -X POST http://localhost/api/scan/deep \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Statut d'un scan
curl http://localhost/api/scan/status/{scan_id} \
  -H "Authorization: Bearer <token>"
```

---

## Endpoints API

| Methode  | Endpoint                | Description                     |
|----------|-------------------------|---------------------------------|
| `POST`   | `/scan/light`           | Lancer un scan rapide           |
| `POST`   | `/scan/deep`            | Lancer un scan complet          |
| `GET`    | `/scan/status/{id}`     | Statut d'un scan                |
| `GET`    | `/scans/history`        | Historique des scans            |
| `GET`    | `/scans/{id}`           | Resultats détaillés d'un scan   |
| `DELETE` | `/scans/{id}`           | Supprimer un scan               |

La documentation interactive complète est disponible sur `http://localhost/api/docs`.

---

## Structure du projet

```
SpiderByte/
├── docker-compose.yml
├── nginx/
│   └── nginx.conf
├── .env.example
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       ├── components/
│       └── pages/
└── backend/
    ├── api/
    │   ├── Dockerfile
    │   ├── main.py
    │   └── routers/
    ├── worker/
    │   ├── tasks.py
    │   └── scanner/
    │       ├── ssl_check.py
    │       ├── header_check.py
    │       ├── nmap_scan.py
    │       ├── sql_injection.py
    │       ├── xss_check.py
    │       └── nuclei_scan.py
    └── database/
        └── models.py
```

### Schema de la base de données

**Table `user`**

| Colonne         | Type    | Description                      |
|-----------------|---------|----------------------------------|
| `user_id`       | PK      | Identifiant unique               |
| `username`      | string  | Nom d'utilisateur                |
| `fullname`      | string  | Nom complet                      |
| `email`         | string  | Adresse email                    |
| `hash_password` | string  | Mot de passe hashé (bcrypt)      |
| `disabled`      | boolean | Compte actif ou désactivé        |

**Table `scans`**

| Colonne      | Type      | Description                              |
|--------------|-----------|------------------------------------------|
| `id`         | PK        | Identifiant unique                       |
| `task_id`    | string    | Identifiant de tâche Celery              |
| `user_id`    | FK        | Référence vers l'utilisateur             |
| `url`        | string    | URL cible du scan                        |
| `status`     | enum      | PENDING / PROGRESS / SUCCESS / FAILED    |
| `result`     | JSON      | Résultats détaillés du scan              |
| `created_at` | timestamp | Date et heure de création                |

---

## Variables d'environnement

```env
# PostgreSQL
POSTGRES_USER=spiderbyte
POSTGRES_PASSWORD=changeme
POSTGRES_DB=spiderbyte_db
DATABASE_URL=postgresql://spiderbyte:changeme@postgres:5432/spiderbyte_db

# Redis
REDIS_URL=redis://redis:6379/0

# Backend
SECRET_KEY=changeme-use-a-strong-random-secret
DEBUG=false

# Celery
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0

# Flower
FLOWER_BASIC_AUTH=admin:password
```

Ne commitez jamais le fichier `.env`. Il est listé dans `.gitignore`.

---

## Stack technique

| Composant          | Technologie              |
|--------------------|--------------------------|
| Backend API        | FastAPI (Python 3.9+)    |
| Frontend           | React 18 + Vite          |
| Base de données    | PostgreSQL 15            |
| Cache / Broker     | Redis                    |
| Tâches asynchrones | Celery                   |
| Reverse proxy      | Nginx                    |
| Scanning dynamique | Nmap, Nuclei, Selenium   |
| Orchestration      | Docker Compose           |
| Sécurité           | JWT, bcrypt, CORS        |

---

## Roadmap

- [x] Authentification JWT (inscription, connexion)
- [x] Scan léger (SSL, headers, Nmap)
- [x] Scan approfondi (SQL injection, XSS, Nuclei)
- [x] Gestion asynchrone des scans (Celery + Redis)
- [x] Historique des scans par utilisateur
- [x] Dashboard Celery (Flower)
- [ ] Export des rapports en PDF
- [ ] Notifications par email à la fin d'un scan
- [ ] Authentification à deux facteurs (2FA)
- [ ] Gestion des rôles et permissions (RBAC)
- [ ] Dashboard avec graphiques et statistiques
- [ ] Comparaison de scans (avant / après)
- [ ] Rate limiting par utilisateur
- [ ] Scaling horizontal des workers Celery
- [ ] Pipeline CI/CD (GitHub Actions)
- [ ] Monitoring (Prometheus + Grafana)

---

## Avertissement légal

SpiderByte est destiné à des fins éducatives et aux audits de sécurité réalisés sur vos propres systèmes ou sur des systèmes pour lesquels vous disposez d'une autorisation explicite et écrite. Toute utilisation sur des systèmes tiers sans autorisation est illégale et contraire à l'éthique. Les auteurs déclinent toute responsabilité en cas d'utilisation abusive de cet outil.
