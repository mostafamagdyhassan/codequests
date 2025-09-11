import os
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

class Config:
    # Application
    APP_NAME = os.getenv("APP_NAME", "task-service")
    APP_PORT = int(os.getenv("APP_PORT", 5000))
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    # Database
    DB_HOST = os.getenv("DB_HOST", "postgres")
    DB_PORT = int(os.getenv("DB_PORT", 5432))
    DB_NAME = os.getenv("DB_NAME", "tasksdb")
    DB_USER = os.getenv("DB_USER", "appuser")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "apppassword")

    # OpenTelemetry
    OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")

    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "changeme-in-prod")

    # Monitoring
    PROMETHEUS_ENABLED = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
