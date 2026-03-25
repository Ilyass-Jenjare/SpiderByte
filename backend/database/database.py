import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
# from sqlalchemy.orm import Session


# On récupère l'URL qu'on a mise dans le docker-compose
# Si on est en local (hors docker), on utilise localhost
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://spideruser:spiderpassword@db:5432/spiderbyte_db")

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Fonction utilitaire pour récupérer la DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

