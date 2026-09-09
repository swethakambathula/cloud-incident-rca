"""Orders service configuration."""
import os

SERVICE_PORT = int(os.getenv("ORDERS_PORT", "8081"))
MAX_INSTANCES = int(os.getenv("ORDERS_MAX_INSTANCES", "4"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
