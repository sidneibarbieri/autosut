import json
import requests

CALDERA_URL = "http://127.0.0.1:8888"
API_KEY = "ADMIN123"   # change if needed
PLANNERS_FILE = "data/backup/planners.json"  # your exported planners JSON file

headers = {
    "key": API_KEY,
    "Content-Type": "application/json"
}

def restore_planners():
    with open(PLANNERS_FILE, "r", encoding="utf-8") as f:
        try:
            planners = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[FAIL] Failed to parse {PLANNERS_FILE}: {e}")
            return

    # If the export is a dict with a "planners" key
    if isinstance(planners, dict) and "planners" in planners:
        planners = planners["planners"]

    if not isinstance(planners, list):
        planners = [planners]

    for planner in planners:
        resp = requests.post(f"{CALDERA_URL}/api/v2/planners", headers=headers, json=planner)
        if resp.status_code == 200:
            print(f"[OK] Restored planner: {planner.get('name', 'unknown')}")
        else:
            print(f"[WARN] Failed to restore planner {planner.get('name', 'unknown')}: {resp.status_code} {resp.text}")

if __name__ == "__main__":
    restore_planners()
