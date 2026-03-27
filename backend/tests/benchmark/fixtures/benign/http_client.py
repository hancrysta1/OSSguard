"""Benign: HTTP client for internal API calls."""
import requests
import logging

logger = logging.getLogger(__name__)

BASE_URL = "http://localhost:8000"


def fetch_users(page: int = 1) -> dict:
    resp = requests.get(f"{BASE_URL}/api/users", params={"page": page})
    resp.raise_for_status()
    return resp.json()


def create_user(name: str, email: str) -> dict:
    resp = requests.post(f"{BASE_URL}/api/users", json={"name": name, "email": email})
    resp.raise_for_status()
    return resp.json()


def update_user(user_id: int, data: dict) -> dict:
    resp = requests.put(f"{BASE_URL}/api/users/{user_id}", json=data)
    resp.raise_for_status()
    return resp.json()
