# SpiderByte - Description Technique et Fonctionnelle Complète

## 📋 Vue d'ensemble de l'Application

**SpiderByte** est une plateforme de **scan de sécurité web automatisée** qui permet aux utilisateurs d'analyser des sites web pour détecter les vulnérabilités de sécurité. L'application propose deux niveaux de scan (Light et Deep) avec authentification utilisateur et historique des scans.

---

## 🏗️ Architecture Générale

L'application suit une **architecture microservices conteneurisée** avec séparation claire des préoccupations:

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT (Navigateur)                  │
│                   Frontend React/Vite                   │
└────────────┬────────────────────────────────────────────┘
             │
┌────────────▼────────────────────────────────────────────┐
│              NGINX (Reverse Proxy / Load Balancer)      │
│              ├─ Port 80 (HTTP)                          │
│              └─ Routage vers API & Frontend             │
└────────────┬────────────────────────────────────────────┘
             │
    ┌────────┴────────┐
    │                 │
┌───▼────────────┐ ┌─▼──────────────┐
│   API FastAPI  │ │   Frontend Dev │
│   (Port 8000)  │ │   (Port 5173)  │
│   - Auth       │ │   - React App  │
│   - CRUD Scan  │ │   - Vite       │
│   - Status     │ │                │
└───┬────────────┘ └──────────────┘
    │
    ├─────────────────────┬──────────────────────┐
    │                     │                      │
┌───▼──────────┐  ┌──────▼─────┐  ┌────────────▼──┐
│  PostgreSQL  │  │    Redis   │  │  Celery       │
│  (Port 5433) │  │ (Port 6379)│  │  Worker Node  │
│              │  │            │  │               │
│ DB: ScanResult│ │ Broker +   │  │ ├─ SSL Check │
│ DB: User      │ │ Result     │  │ ├─ Header    │
│ Tables        │ │ Backend    │  │ ├─ SQL Inj   │
│              │  │            │  │ ├─ XSS       │
└──────────────┘  └────────────┘  │ ├─ Nmap      │
                                   │ └─ Nuclei   │
                 ┌─────────────────▼─────────────┐
                 │  Selenium Hub (Chrome)        │
                 │  (Port 4444, VNC: 7900)       │
                 │  - Automation browser testing │
                 └───────────────────────────────┘
```

---

## 🔧 Stack Technologique

### **Frontend**
| Technologie | Version | Purpose |
|---|---|---|
| React | 18.3.1 | Framework UI |
| React Router DOM | 7.13.1 | Routing |
| Vite | 5.4.10 | Build tool & Dev server |
| Tailwind CSS | 4.2.2 | Styling |
| Node.js | 20-alpine | Runtime |

### **Backend API**
| Technologie | Version | Purpose |
|---|---|---|
| FastAPI | Latest | REST API Framework |
| Uvicorn | Latest | ASGI Server |
| Python | 3.x | Runtime |
| Pydantic | Latest | Data validation |

### **Authentication & Security**
| Library | Purpose |
|---|---|
| passlib[bcrypt] | Password hashing |
| bcrypt 4.0.1 | Cryptographic signing |
| python-jose[cryptography] | JWT tokens |

### **Data & Persistence**
| Technology | Port | Purpose |
|---|---|---|
| PostgreSQL 15 | 5433 | Primary database |
| SQLAlchemy | - | ORM |
| psycopg2-binary | - | PostgreSQL adapter |
| Redis (Alpine) | 6379 | Celery broker & cache |

### **Async Task Processing**
| Technology | Purpose |
|---|---|
| Celery | Distributed task queue |
| Redis | Message broker |

### **Scanning & Security Tools**
| Tool | Purpose |
|---|---|
| Selenium | Browser automation (XSS, JavaScript testing) |
| BeautifulSoup4 | HTML parsing |
| Nmap | Port & service scanning |
| Nuclei | Vulnerability scanning engine |
| Requests | HTTP requests |

### **Infrastructure**
| Technology | Purpose |
|---|---|
| Docker | Containerization |
| Docker Compose | Orchestration |
| Nginx (Alpine) | Reverse proxy, load balancing |

---

## 📦 Composants Détaillés

### **1. Base de Données PostgreSQL**
**Schéma:**

#### Table `user` (Authentification)
```sql
- user_id (PK, Integer)
- username (String, Indexed)
- fullname (String)
- email (String, Indexed, Unique)
- hash_password (String) -- bcrypt hashée
- disabled (Boolean, default=False)
- Relation: 1 User -> N ScanResults
```

#### Table `scans` (Résultats de scan)
```sql
- id (PK, Integer)
- task_id (String, Unique) -- ID de tâche Celery
- user_id (FK) -- Propriétaire du scan
- url (String, Indexed) -- URL scannée
- status (String) -- PENDING|RUNNING|SUCCESS|ERROR
- result (JSON) -- Résultats détaillés du scan
- created_at (DateTime, server-generated) -- Timestamp
```

**Connexion:** `postgresql://spideruser:spiderpassword@db:5432/spiderbyte_db`

---

### **2. API REST FastAPI (Port 8000)**

**Endpoints Principaux:**

#### **Authentification**
```
POST   /register         - Créer un compte utilisateur
POST   /login           - Obtenir JWT token
GET    /me              - Récupérer profil utilisateur (auth required)
```

#### **Scanning**
```
POST   /scan/light      - Lancer scan léger (auth required, token required)
POST   /scan/deep       - Lancer scan complet (auth required, token required)
GET    /scan/status/{id} - Vérifier statut du scan (auth required)
```

**Sécurité:** Les endpoints vérifient l'ownership (un utilisateur ne peut voir que ses propres scans)

#### **Historique**
```
GET    /scans/history   - Récupérer tous les scans de l'utilisateur
GET    /scans/{id}      - Détail d'un scan spécifique
DELETE /scans/{id}      - Supprimer un scan
```

**Headers requis pour l'authentification:**
```
Authorization: Bearer <JWT_TOKEN>
```

**CORS Configuration:**
- `http://localhost:5173` (dev frontend)
- `http://127.0.0.1:5173` (local)

---

### **3. Frontend React + Vite (Port 5173)**

**Architecture Componentsielle:**

```
src/
├── components/
│   ├── AuthForm.jsx          -- Formulaire login/signup
│   ├── HeroSection.jsx        -- Accueil
│   ├── Navbar.jsx             -- Navigation
│   ├── ProtectedRoute.jsx      -- Authentification guard
│   ├── ScanCard.jsx            -- Affichage d'un scan
│   ├── VulnerabilityCard.jsx   -- Affichage vulnérabilité
│   ├── dashboard/
│   │   ├── VulnerabilityList.jsx    -- Liste des vulnérabilités
│   │   ├── VulnerabilityDetails.jsx  -- Détails complets
│   │   ├── VulnerabilityDrawer.jsx   -- Drawer/Modal
│   │   ├── VulnerabilityItem.jsx     -- Item liste
│   │   └── severity.js               -- Utilitaires sévérité
│   └── SiteFooter.jsx         -- Footer
├── pages/
│   ├── LandingPage.jsx        -- Accueil public
│   ├── LoginPage.jsx          -- Page connexion
│   ├── SignupPage.jsx         -- Page inscription
│   └── DashboardPage.jsx      -- Dashboard utilisateur
├── context/
│   ├── AuthContext.jsx        -- État auth global
│   ├── ScanContext.jsx        -- État scans
│   └── ToastContext.jsx       -- Notifications toast
├── App.jsx                    -- Routing principal
└── main.jsx                   -- Entry point
```

**Fonctionnalités Frontend:**
- Système d'authentification (login/signup/JWT)
- Lancement de scans (Light/Deep)
- Affichage en temps réel du statut
- Historique des scans
- Détails des vulnérabilités découvertes
- Système de notification (toast)
- Design responsive Tailwind CSS

---

### **4. Celery Worker (Task Queue)**

**Configuration:**
- **Broker:** Redis (redis://redis:6379/0)
- **Backend:** Redis (pour les résultats)
- **Serialization:** JSON

**Tâche Principale:** `perform_scan(url, user_id, scan_type)`

**Flux d'exécution:**
1. Reçoit la demande via Redis
2. Sélectionne les modules de scan appropriés (light/deep)
3. Exécute les modules en séquence
4. Agrège les résultats
5. Sauvegarde dans PostgreSQL
6. Retourne le statut via `update_state()`

**États de tâche:**
- `PENDING` - En attente
- `PROGRESS` - En cours
- `SUCCESS` - Complété
- `ERROR` - Erreur d'exécution
- `RETRY` - Tentative de retry

---

### **5. Modules de Scan Sécurité**

#### **Light Scan** (rapide, ~2-5 min)
1. **SSL Check** - Validation certificat SSL/TLS
   - Vérify certificat valide
   - Date d'expiration
   - Chain de certificats
   - Algorithme de signature

2. **Header Check** - Analyse des headers de sécurité
   - HSTS
   - X-Content-Type-Options
   - X-Frame-Options
   - CSP (Content Security Policy)
   - Autres headers critiques

3. **Nmap Scan** - Scan de ports avec Nmap
   - Détection de ports ouverts
   - Services disponibles
   - Version detection

#### **Deep Scan** (complet, ~15-30 min)
Inclut tous les modules Light PLUS:

4. **SQL Injection Detection** - Test d'injection SQL
   - Crawl du site (max 40 pages)
   - Identification des formulaires
   - Test avec payloads SQL
   - Analyse des réponses (détection d'erreurs DB)
   - Scoring de confiance (HIGH/MEDIUM/LOW)

5. **XSS Detection** - Test Cross-Site Scripting
   - Utilise Selenium pour automation
   - Test des champs d'input
   - Injection de payloads JavaScript
   - Détection via DOM inspection

6. **Nuclei Scan** - Vulnerability scanning engine
   - Templates YAML de vulnérabilités
   - Détection d'exposition de fichiers
   - Misconfigurations
   - Plugins d'applications

7. **SQL Injection Commenter** - Modules complémentaires

**Chaque module retourne:**
```json
{
  "scan_type": "MODULE_NAME",
  "status": "SUCCESS|ERROR",
  "details": { /* résultats spécifiques */ }
}
```

---

### **6. Selenium Hub (Port 4444)**

**Image:** `selenium/standalone-chrome:4.7.2-20221219`

**Capacités:**
- Browser automation pour tests XSS
- Exécution JavaScript
- Interaction DOM
- VNC viewer (port 7900) pour debugging

**Configuration:**
- Max instances: 5
- Max sessions: 5
- Shared memory: 2GB
- Chrome stable

---

### **7. Nginx (Port 80)**

**Rôle:** Reverse proxy et load balancer

**Configuration:**
```
- Écoute sur Port 80
- Routes:/api/* → vers API (8000)
- Routes/* → vers Frontend (5173)
- Gestion du cache
- Compression des réponses
```

---

## 🔐 Flux d'Authentification

### **Inscription (Signup)**
```
1. User POST /register {email, username, fullname, password}
2. API valide email unique
3. API hash password avec bcrypt
4. Crée User en DB
5. Retourne succès
```

### **Connexion (Login)**
```
1. User POST /login {email, password}
2. API récupère User de DB
3. API vérifie password vs hash bcrypt
4. Si valide: génère JWT token (contient email)
5. Retourne token au client
6. Client stocke token (localStorage/sessionStorage)
```

### **Appel authentifié**
```
1. Client POST /scan/deep {url}
   Headers: Authorization: Bearer <JWT_TOKEN>
2. API décode JWT → récupère email
3. API récupère User_id de DB
4. API crée ScanResult en DB
5. API lance tâche Celery perform_scan()
6. Retourne task_id
```

---

## 📊 Flux Général d'un Scan

```
1. USER FRONTEND
   └─ Clique "Scan Deep" pour "https://example.com"

2. FRONTEND (React)
   └─ POST /api/scan/deep
      {target: "https://example.com"}
      Headers: {Authorization: "Bearer JWT_TOKEN"}

3. API FASTAPI
   ├─ Valide JWT token
   ├─ Récupère User_id
   ├─ Crée ScanResult en DB
   │  └─ status = "PENDING"
   ├─ Lance tâche Celery
   │  └─ perform_scan.delay(url, user_id, "deep")
   └─ Retourne {task_id, scan_id, status}

4. REDIS BROKER
   └─ Queue: celery task → Celery Worker

5. CELERY WORKER
   ├─ Reçoit perform_scan()
   ├─ status = "PROGRESS"
   ├─ Pour chaque module (deep scan = 6 modules):
   │  ├─ SSL Check → {certificat info}
   │  ├─ Header Check → {security headers}
   │  ├─ SQL Injection → {potential vulnerabilities}
   │  ├─ XSS Test → {xss vectors}
   │  ├─ Nmap Scan → {open ports}
   │  └─ Nuclei → {known vulns}
   ├─ Agrège tous les résultats
   ├─ Stocke en REDIS (pour async retrieval)
   └─ Sauvegarde en PostgreSQL
      └─ UPDATE scans SET status='SUCCESS', result=JSON

6. FRONTEND (Polling)
   ├─ Interroge GET /scan/status/{task_id} toutes les 2-5 sec
   └─ Affiche les résultats quand status='SUCCESS'

7. FRONTEND (Dashboard)
   └─ Affiche: URL, Date, Vulnérabilités, Sévérité
```

---

## 💾 Modèle de Données

### **Structures Principales**

**ScanRequest (Input):**
```json
{
  "target": "https://example.com"
}
```

**ScanResponse (Output):**
```json
{
  "task_id": "celery-uuid-xxx",
  "scan_id": 42,
  "url": "https://example.com",
  "status": "PENDING",
  "scan_type": "deep",
  "created_at": "2024-01-01T12:00:00Z"
}
```

**Résultat Scan Complet:**
```json
{
  "scan_type": "deep",
  "execution_time_seconds": 125.5,
  "modules": {
    "ssl_check": {
      "status": "SUCCESS",
      "details": {
        "valid": true,
        "issuer": "Let's Encrypt",
        "expires_in_days": 89,
        "certificate_chain": []
      }
    },
    "header_check": {
      "status": "SUCCESS",
      "details": {
        "headers": {...},
        "missing_headers": ["HSTS", "X-Frame-Options"],
        "recommendations": [...]
      }
    },
    "sql_injection": {
      "status": "SUCCESS",
      "details": {
        "vulnerable_endpoints": [],
        "suspicious_patterns": [],
        "confidence": "LOW"
      }
    },
    "xss_check": {
      "status": "SUCCESS",
      "details": {...}
    },
    "nmap_scan": {
      "status": "SUCCESS",
      "details": {
        "open_ports": [80, 443],
        "services": ["http", "https"]
      }
    },
    "nuclei": {
      "status": "SUCCESS",
      "details": {
        "vulnerabilities": [...]
      }
    }
  }
}
```

---

## ⚙️ Variables d'Environnement

```
# PostgreSQL
POSTGRES_USER=spideruser
POSTGRES_PASSWORD=spiderpassword
POSTGRES_DB=spiderbyte_db

# Backend API
PYTHONPATH=/app
DATABASE_URL=postgresql://spideruser:spiderpassword@db:5432/spiderbyte_db
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Frontend
VITE_API_BASE_URL=/api

# Selenium
SE_NODE_MAX_INSTANCES=5
SE_NODE_MAX_SESSION=5
```

---

## 📈 Exigences en Ressources

### **CPU**
- **Frontend:** ~0.1 CPU (dev mode)
- **API:** ~0.2 CPU (idle), 0.5-1 CPU (scanning)
- **Worker:** ~1-2 CPU par scan (dépend du scan type)
- **Selenium:** ~1 CPU par browser session
- **Total:** 2-4 CPU recommandés

### **RAM**
- **PostgreSQL:** 512 MB - 1 GB
- **Redis:** 256 MB - 512 MB
- **API:** 256 MB - 512 MB
- **Frontend:** 128 MB - 256 MB
- **Worker:** 512 MB - 1 GB (dépend des modules)
- **Selenium:** 2-3 GB (shm_size=2gb)
- **Total:** 4-7 GB recommandés

### **Stockage**
- **PostgreSQL data:** 50 GB - 500 GB (dépend de l'historique)
- **Log volumes:** 10-100 GB
- **Container images:** ~3-5 GB
- **Total minimum:** 100 GB

### **Bande passante**
- **HTTP requêtes:** ~1-10 Mbps par scan
- **Blockchain scanning:** Variable
- **Data export:** ~10-100 Mbps par utilisateur

---

## 🔄 Scalabilité

### **Horizontal Scaling**
```
- ✅ API: Peut scale horizontalement (stateless)
- ✅ Celery Workers: Peut ajouter N workers
- ✅ Frontend: Peut replicate (nginx load balance)
- ⚠️ PostgreSQL: Nécessite master-slave replication
- ⚠️ Redis: Peut utiliser Sentinel mode
```

### **Goulots d'Étranglement Potentiels**
1. **Selenium Hub** - Browser instances limités (5 max actuellement)
   - Solution: Scaler horizontalement avec multiple Selenium instances
2. **PostgreSQL** - Connexions DB limitées
   - Solution: Connection pooling avec PgBouncer
3. **Nmap/Nuclei** - Long-running scans
   - Solution: Timeout configuration + retry policy

---

## 🚀 Déploiement Actuel

### **Environnement Local (Docker Compose)**
```bash
docker-compose up -d
```

Services conteneurisés:
- ✓ PostgreSQL 15
- ✓ Redis Alpine
- ✓ FastAPI API
- ✓ React Frontend
- ✓ Celery Worker
- ✓ Selenium Standalone Chrome
- ✓ Nginx Reverse Proxy

---

## 📋 Dépendances Externes

### **Requis pour fonctionner**
1. **Internet** - Pour scans externes HTTP/HTTPS
2. **DNS Résolution** - Pour lookups domaines
3. **Nmap** - Pré-installé dans container Python
4. **Nuclei** - Pré-installé dans container Python

### **Recommandé**
1. **VPN/Proxy** - Pour masquer IP source
2. **Rate Limiting** - Pour respecter ToS (robots.txt)
3. **Monitoring** - Prometheus/Grafana
4. **Logging Centralisé** - ELK Stack

---

## 🛡️ Considérations de Sécurité

### **Points Sensibles**
1. **JWT Tokens** - Pas de rotation actuellement
2. **Password Storage** - Bcrypt OK, mais pas de 2FA
3. **Input Validation** - Pydantic validations en place
4. **CORS** - Limité à localhost (dev config)
5. **HTTPS** - Non forcé actuellement (80 only)
6. **Rate Limiting** - Non implémenté (vulnérable au brute-force)

### **Recommandations**
- ✓ Activer HTTPS/TLS obligatoire
- ✓ Implémenter rate limiting
- ✓ Ajouter 2FA
- ✓ Rotation des JWT tokens
- ✓ WAF (Web Application Firewall)
- ✓ Audit logging pour les actions critiques

---

## 📊 Cas d'Usage & Performance

### **Scan Léger (Light)**
- **Temps:** 2-5 minutes
- **Modules:** 3 (SSL, Headers, Nmap)
- **CPU:** ~0.5-1 CPU
- **RAM:** ~200-300 MB

### **Scan Complet (Deep)**
- **Temps:** 15-30 minutes
- **Modules:** 6 (SSL, Headers, SQL Inj, XSS, Nmap, Nuclei)
- **CPU:** ~1-2 CPU
- **RAM:** ~500-800 MB

### **Concurrent Users**
- **Avec infrastructure actuelle:** 2-3 scans simultanés
- **Avec scaling:** Illimité (ajouter workers Celery)

---

## 🌐 Architecture de Déploiement Production

Pour un hébergement cloud optimisé, recommandé:

### **Option 1: Kubernetes (Scalabilité Haute)**
```yaml
- Namespace: spiderbyte
- Deployments:
  - API (3 replicas)
  - Frontend (2 replicas)
  - Workers Celery (5-10 replicas auto-scale)
  - Selenium Hub (2 replicas)
- Services:
  - PostgreSQL StatefulSet
  - Redis Sentinel
  - Nginx Ingress
- Storage:
  - PersistentVolume PostgreSQL (50-500GB)
  - ConfigMaps pour config
```

### **Option 2: Docker Swarm (Modérée)**
```
- Manager node (1)
- Worker nodes (2-4)
- Services: API, Worker, Frontend, Nginx
- Volumes: PostgreSQL, Redis
```

### **Option 3: VMs IaaS (AWS, Azure, GCP)**
```
- RDS PostgreSQL (managed)
- ElastiCache Redis (managed)
- EC2 instances (API + Workers)
- ECS pour Celery workers
- CloudFront CDN
```

---

## 📌 Conclusion

**SpiderByte** est une application de scan de sécurité web **moderne, containerisée et scalable** avec:

| Caractéristique | Détail |
|---|---|
| **Type** | SaaS de sécurité |
| **Architecture** | Microservices + Queue tasks |
| **Scalabilité** | Horizontale (workers Celery) |
| **Performance** | 2-30 min pour scans complets |
| **Charge típica** | 2-10 scans/jour par utilisateur |
| **Coûts** | Modérés (CPU/RAM/Storage) |
| **Uptime requis** | 95%+ (SLA) |
| **Compliance** | GDPR-ready (audit trails) |

---

## 📞 Recommandations Hébergement Résumé

**⭐ Idéal:** Kubernetes managé (GKE, EKS, AKS)
- Scaling automatique
- Haute disponibilité
- Monitoring intégré

**💰 Budget:** Docker Compose + VPS 6-8 CPU, 8 GB RAM

**🚀 Maximum Performance:** Cloud provider PaaS
- RDS PostgreSQL
- Elastiache Redis
- Auto-scaling groups
- CloudDN/CDN

---

*Document généré pour analyse d'hébergement - SpiderByte Security Platform*
