# SpiderByte - Résumé Opérationnel pour Recommandations d'Hébergement

## Quick Summary

**SpiderByte** = Plateforme de **scan de sécurité web automatisé** avec interface utilisateur, queue de tâches asynchrones, et historique scanné/stocké.

---

## 🏗️ Architecture en One Page

```
Users (Frontend React) 
    ↓
Nginx (Reverse Proxy, Port 80)
    ↓ ↓
API (FastAPI 8000) ← PostgreSQL DB (5433)
    ↓                  ↑
Redis (6379) ─→ Celery Workers ─→ Selenium (4444)
    ↑__________________|
              Queue d'execution
```

---

## 📦 Stack Technologie

| Couche | Technology | Criticité |
|--------|-----------|-----------|
| **Frontend** | React 18 + Vite + Tailwind CSS | Medium |
| **API** | FastAPI + Uvicorn | **CRITIQUE** |
| **Auth** | JWT + bcrypt | **CRITIQUE** |
| **BDD** | PostgreSQL 15 | **CRITIQUE** |
| **Cache/Queue** | Redis + Celery | **CRITIQUE** |
| **Scanning** | Selenium, Nmap, Nuclei, BeautifulSoup | High |
| **Infrastructure** | Docker Compose, Nginx | **CRITIQUE** |

---

## 🔧 Services Docker Obligatoires

```yaml
1. PostgreSQL 15
   - Port: 5433 (internal 5432)
   - Storage: 50-500 GB (dépend historique)
   - Credentials: spideruser / DB: spiderbyte_db

2. Redis (Message Broker)
   - Port: 6379
   - RAM: 256MB - 1GB
   - Fonction: Celery broker + result backend

3. FastAPI API
   - Port: 8000 (internal)
   - CPU: 0.2-1 CPU
   - RAM: 256-512 MB
   - Env: CELERY_BROKER_URL, DATABASE_URL, CORS_ORIGINS

4. Celery Worker
   - CPU: 1-2 CPU par workers
   - RAM: 512MB - 1GB
   - Exécute: scan_task (SSL, Headers, SQL Inj, XSS, Nmap, Nuclei)

5. Selenium Standalone Chrome
   - Port: 4444 (automation), 7900 (VNC debug)
   - RAM: 2GB (shm)
   - CPU: 1 CPU par session

6. React Frontend (Dev ou Built)
   - Port: 5173 (dev) ou 3000 (build)
   - RAM: 128-256 MB

7. Nginx (Reverse Proxy)
   - Port: 80/443 (public)
   - Routes: /api/* → API, /* → Frontend
```

---

## 📊 Ressources Requises

| Composant | Min | Recommended | Peak |
|-----------|-----|-------------|------|
| **CPU Total** | 2 | 4 | 8 |
| **RAM Total** | 4 GB | 8 GB | 16 GB |
| **Storage (DB)** | 50 GB | 100 GB | 500+ GB |
| **Bandwidth** | 1 Mbps | 10 Mbps | 100+ Mbps |

### **RAM Breakdown**
- PostgreSQL: 512MB - 1GB
- Redis: 256MB - 512MB
- API: 256MB
- Workers (1): 512MB - 1GB
- Selenium: 2GB
- Frontend: 128MB - 256MB
- **Total: 4-7 GB recommandé**

### **CPU Breakdown**
- API: 0.2-0.5 CPU
- Worker (concurrent): 1-2 CPU par scan
- Selenium: 1 CPU par session
- Autres: 0.5 CPU
- **Total: 2-4 CPU recommandé**

---

## ⏱️ Performance & Throughput

### **Temps d'exécution des scans**
- **Light Scan (SSL, Headers, Nmap)**: 2-5 minutes
- **Deep Scan (Light + SQL Inj + XSS + Nuclei)**: 15-30 minutes

### **Scalabilité**
- **Scans simultanés (actuellement)**: 2-3 (limité par Selenium)
- **Avec infrastructure scaled**: N workers = N concurrent scans
- **Utilisateurs concurrent**: 10-50+ (dépend de fréquence de scans)

### **Bottlenecks**
1. Selenium Hub (max 5 instances) → Limiter les XSS tests
2. Nmap execution (~3-5 min/scan) → CPU-intensive
3. PostgreSQL connections → Connection pooling needed
4. Network I/O → Rate limiting important

---

## 🔐 Données Sensibles

### **Stored in PostgreSQL**
- User credentials (email, bcrypt password hash)
- Scan history (URL, results, timestamps)
- User preferences

### **Stored in Redis**
- Celery task results (temporary, TTL)
- Session data (optional)

### **Network Data**
- API traffic → HTTPS required in production
- JWT tokens → Should use secure cookies

---

## 🚀 Déploiement Options

### **Option A: Local/Dev (Docker Compose)**
✓ `docker-compose up -d`
- Viable pour up to 10 users
- Ressources: 6-8 GB RAM, 2-4 CPU
- Cost: $50-100/month (cheap VPS)

### **Option B: Cloud VPS (AWS EC2/DigitalOcean/Linode)**
- Single node: 4 CPU, 8 GB RAM
- Avec RDS PostgreSQL (managed)
- Avec ElastiCache Redis (managed)
- Cost: $150-300/month
- Scaling: Manual (ajouter workers manuellement)

### **Option C: Kubernetes (Production)**
- Auto-scaling for workers
- High availability (replicas)
- Monitoring built-in
- Cost: $200-500/month (managed K8s)
- Scale: Automatic (Horizontal Pod Autoscaler)

### **Option D: Serverless (AWS Lambda + RDS)**
- Limité (timeout 15 min) ❌ Pas viable pour deep scans (30 min)
- Rejected pour ce use case

---

## 🌍 Configuration Multi-Region

```
Region 1 (EU)                    Region 2 (US)
├─ PostgreSQL Primary     ----RDS Replication----  PostgreSQL Replica
├─ Redis                                          Redis (read-only)
├─ API + Workers                                  API + Workers (failover)
└─ Nginx LB (primary)                             Nginx LB (secondary)

CloudFlare / Route53 → DNS failover
```

---

## 🛡️ Security Checklist

- [ ] HTTPS/TLS enforced (443 only)
- [ ] WAF (Web Application Firewall)
- [ ] Rate limiting on API (brute-force protection)
- [ ] JWT token rotation (hourly)
- [ ] 2FA for user accounts
- [ ] Audit logging (scan history)
- [ ] Secrets management (env vars → AWS Secrets Manager)
- [ ] VPC isolation for databases
- [ ] DDoS protection
- [ ] Regular security updates

---

## 📈 Monitoring & Observability

### **Key Metrics to Monitor**
```
API Performance:
  - Response time < 200ms
  - Error rate < 1%
  - Availability > 99.5%

Celery Workers:
  - Queue length
  - Task execution time
  - Failed tasks

PostgreSQL:
  - Connection count
  - Query time
  - Disk usage growth rate

Redis:
  - Memory usage
  - Hit rate
  - Evictions

Infrastructure:
  - CPU usage
  - Memory pressure
  - Disk I/O
  - Network bandwidth
```

### **Recommended Tools**
- Prometheus + Grafana (metrics)
- ELK Stack (logging)
- Sentry (error tracking)
- DataDog / New Relic (APM)

---

## 💰 Estimated Costs (Monthly)

### **Dev/Testing Environment**
- Single VM (4 CPU, 8 GB): $100-150
- Managed RDS PostgreSQL: $150-200
- Managed Redis: $50-75
- Bandwidth & storage: $20-50
- **Total: $320-475/month**

### **Production Environment (1000 users)**
- Load-balanced VMs (2x 4 CPU, 8 GB): $200-300
- Managed RDS PostgreSQL (xl): $300-500
- Managed Redis (premium): $100-150
- CloudFront CDN: $50-100
- Monitoring & backup: $50-100
- **Total: $700-1150/month**

### **Enterprise (10k+ users, HA)**
- Kubernetes cluster (3 masters, 10 workers): $500-800
- Database as JSON replication: $500-1000
- Multi-region failover: +50%
- Premium support: +$200-500
- **Total: $1500-3000+/month**

---

## ✅ Pre-Deployment Checklist

- [ ] Modify docker-compose for production (remove `--reload`)
- [ ] Set strong PostgreSQL password
- [ ] Generate JWT secret key
- [ ] Configure CORS_ORIGINS for domain
- [ ] Setup HTTPS certificates (Let's Encrypt)
- [ ] Enable database backups
- [ ] Setup monitoring & alerting
- [ ] Create disaster recovery plan
- [ ] Performance load testing
- [ ] Security penetration testing
- [ ] Document runbooks
- [ ] Setup CI/CD pipeline

---

## 📋 Dimensioning Recommendation

### **Small (10-50 active users)**
- **VM size**: 4 CPU, 8 GB RAM
- **Database**: PostgreSQL 50 GB SSD
- **Redis**: 1GB memory
- **Estimated cost**: $300/month

### **Medium (50-500 users)**
- **VM size**: 8 CPU, 16 GB RAM (or 2x 4 CPU)
- **Database**: PostgreSQL 200 GB SSD + replication
- **Redis**: 5 GB memory
- **Workers**: 3-5 Celery instances
- **Estimated cost**: $800/month

### **Large (500-5000+ users)**
- **Kubernetes cluster** with auto-scaling
- **Database**: Managed PostgreSQL enterprise (HA)
- **Redis**: Managed cluster (Sentinel)
- **CDN**: CloudFront / Akamai
- **Estimated cost**: $2000-3000+/month

---

## 🎯 Key Recommendations for Gemini

1. **Must Use Containers** → Docker/Kubernetes (not viable on shared hosting)
2. **Managed Services Preferred** → RDS, ElastiCache, Cloud-native storage
3. **Minimum 8 GB RAM** → Selenium + concurrent workers demand it
4. **At least 2 CPU cores** → Light load, 4+ for production
5. **Fast SSD storage** → PostgreSQL needs fast I/O
6. **Reliable network** → Scans need stable internet for external URLs
7. **HTTPS mandatory** → Production must use 443
8. **Separate prod/dev** → Different credentials, monitoring levels
9. **Auto-scaling critical** → Celery workers should scale with load
10. **Backup strategy** → Daily snapshots, replicas recommended

---

*Ready to present to Gemini for infrastructure recommendations*
