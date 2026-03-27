#!/usr/bin/env python3
"""LLM 판단 빠른 테스트 - 2개 샘플만"""
import json, re, time, sys, os
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

import ollama

BENIGN = "tests/benchmark/fixtures/benign/base64_legit.py"
MALICIOUS = "tests/benchmark/fixtures/malicious/backdoor_exec.py"

PROMPT = """You are a code security analyst. Keywords [{flags}] were detected.
Is this code SAFE (image processing, git commands, API calls) or MALICIOUS (data theft, RCE, reverse shell)?
Reply JSON ONLY: {{"verdict":"safe" or "malicious","reason":"1 sentence"}}

Code:
{code}"""

for label, path, flags in [
    ("BENIGN base64_legit.py", BENIGN, "base64"),
    ("MALICIOUS backdoor_exec.py", MALICIOUS, "exec, base64, os.system"),
]:
    code = open(path).read()[:1500]
    prompt = PROMPT.format(flags=flags, code=code)
    print(f"Testing: {label}...", flush=True)
    t = time.time()
    resp = ollama.chat(
        model="llama3.2:1b",
        messages=[{"role": "user", "content": prompt}],
        options={"temperature": 0.1, "num_predict": 128},
    )
    elapsed = time.time() - t
    content = resp["message"]["content"].strip()
    print(f"  Time: {elapsed:.1f}s", flush=True)
    print(f"  Response: {content[:300]}", flush=True)
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if m:
        parsed = json.loads(m.group())
        print(f"  Verdict: {parsed.get('verdict')}", flush=True)
        print(f"  Reason: {parsed.get('reason')}", flush=True)
    print(flush=True)
