# On part d'une version légère de Python
FROM python:3.9-slim

# On empêche Python de garder des fichiers .pyc inutiles
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# On crée un dossier de travail
WORKDIR /app

# On installe les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# On copie tout ton code 'backend' dans le conteneur
COPY . .

# 1. Installer wget et unzip (nécessaires pour télécharger et extraire Nuclei)
RUN apt-get update && apt-get install -y wget unzip nmap

# 2. Télécharger la version précompilée de Nuclei pour Linux
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.7.0/nuclei_3.7.0_linux_amd64.zip

# 3. Extraire l'archive et déplacer le programme dans le dossier global des exécutables
RUN unzip nuclei_3.7.0_linux_amd64.zip
RUN mv nuclei /usr/local/bin/

# 4. Nettoyer l'archive zip pour alléger l'image Docker
RUN rm nuclei_3.7.0_linux_amd64.zip

# 5. Télécharger les templates de failles (pour ne pas perdre de temps à chaque scan)
RUN nuclei -update-templates