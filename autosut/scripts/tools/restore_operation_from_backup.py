import json
import requests
from pathlib import Path

CALDERA_URL = "http://127.0.0.1:8888"
API_KEY = "ADMIN123"   # change if needed
OPERATIONS_FILE = "data/backup/operations.json"  # your backup file

def restore_operations():
    ops_path = Path(OPERATIONS_FILE)
    if not ops_path.exists():
        print(f"[FAIL] File not found: {OPERATIONS_FILE}")
        return

    with open(ops_path, "r", encoding="utf-8") as f:
        try:
            operations = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[FAIL] Failed to parse JSON: {e}")
            return

    if not isinstance(operations, list):
        operations = [operations]

    headers = {
        "Content-Type": "application/json",
        "key": API_KEY
    }

    for op in operations:
        try:
            resp = requests.post(
                f"{CALDERA_URL}/api/v2/operations",
                headers=headers,
                json=op
            )
            if resp.status_code == 200:
                print(f"[OK] Restored operation: {op.get('name')} ({op.get('id')})")
            else:
                print(f"[WARN] Failed to restore {op.get('name')}: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"[FAIL] Error restoring {op.get('name')}: {e}")

if __name__ == "__main__":
    restore_operations()
