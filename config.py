import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://certwatch:certwatch@db:3306/certwatch",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CERT_EXPIRY_WARNING_DAYS = int(os.getenv("CERT_EXPIRY_WARNING_DAYS", "30"))
    ACME_DIRECTORY_URL = os.getenv("ACME_DIRECTORY_URL", "https://pebble:14000/dir")
    ACME_EMAIL = os.getenv("ACME_EMAIL", "certwatch@example.invalid")
    ACME_DOMAIN = os.getenv("ACME_DOMAIN", "example.com")
    ACME_CA_CERT = os.getenv("ACME_CA_CERT", "/app/pebble.minica.pem")
    ACME_STORAGE = os.getenv("ACME_STORAGE", "/app/data/acme")
    ACME_CERT_STORAGE = os.getenv("ACME_CERT_STORAGE", "/app/certificates/acme")
