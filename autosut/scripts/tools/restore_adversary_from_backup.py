import json
import requests
from pathlib import Path

CALDERA_URL = "http://127.0.0.1:8888"
API_KEY = "ADMIN123"   # change if you use a different key
ADVERSARIES_FILE = "data/backup/adversaries.json"  # your backup file

def restore_adversaries():
    adv_path = Path(ADVERSARIES_FILE)
    if not adv_path.exists():
        print(f"[FAIL] File not found: {ADVERSARIES_FILE}")
        return

    with open(adv_path, "r", encoding="utf-8") as f:
        try:
            adversaries = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[FAIL] Failed to parse JSON: {e}")
            return

    # Some exports may be a single object instead of a list
    if not isinstance(adversaries, list):
        adversaries = [adversaries]

    headers = {
        "Content-Type": "application/json",
        "key": API_KEY
    }

    for adv in adversaries:
        try:
            resp = requests.post(
                f"{CALDERA_URL}/api/v2/adversaries",
                headers=headers,
                json=adv
            )
            if resp.status_code == 200:
                print(f"[OK] Restored adversary: {adv.get('name')} ({adv.get('adversary_id')})")
            else:
                print(f"[WARN] Failed to restore {adv.get('name')}: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"[FAIL] Error restoring {adv.get('name')}: {e}")

if __name__ == "__main__":
    restore_adversaries()
