import requests
from pathlib import Path
import sys
import json
from typing import List, Dict, Any
import requests
import subprocess
import time

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    import config
except ImportError:
    print("[FAIL] Could not import 'config' module. Make sure your PYTHONPATH includes the project root.")
    sys.exit(1)

API_URL = "http://localhost:8888/api/v2"
API_KEY = config.CALDERA_API_KEY_RED

headers = {"KEY": API_KEY}


# 1️⃣ Fetch all adversary IDs from CALDERA
resp = requests.get(f"{API_URL}/adversaries", headers=headers)
if resp.status_code != 200:
    print(f"[FAIL] Failed to fetch adversaries: {resp.status_code} - {resp.text}")
    exit(1)

adversaries = resp.json()  # v2 API returns a list of adversary objects

if not adversaries:
    print("[WARN] No adversaries found in CALDERA.")
    exit(0)

# 2️⃣ Loop through adversaries and create operations
for count, adv in enumerate(adversaries, start=1):
    adv_id = adv["adversary_id"]
    op_name = f"OP{count:03d}"
    print(f"Creating operation: {op_name} with adversary ID: {adv_id}")
    time.sleep(1)

    # Call CALDERA lib/operation.py CLI
    result = subprocess.run([
        "python3", "lib/operation.py", "create",
        "--name", op_name,
        "--group", "red",
        "--planner", "atomic",
        "--jitter", "2/8",
        "--adversary", adv_id
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[OK] Operation {op_name} created successfully.")
    else:
        print(f"[FAIL] Failed to create {op_name}:\n{result.stderr}")

    time.sleep(1)  # optional sleep between operations
