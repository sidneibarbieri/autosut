#!/usr/bin/env python3
"""
Simplified Caldera API Test - Mock for Pipeline Testing
"""

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


class CalderaMockHandler(BaseHTTPRequestHandler):
    """Mock Caldera API for testing"""

    def do_GET(self):
        if self.path == "/api/v2/abilities":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            # Return mock abilities
            mock_abilities = [
                {
                    "ability_id": "mock-ability-1",
                    "name": "Unix Shell",
                    "technique_id": "T1059.004",
                    "tactic": "execution",
                },
                {
                    "ability_id": "mock-ability-2",
                    "name": "File Discovery",
                    "technique_id": "T1083",
                    "tactic": "discovery",
                },
            ]
            self.wfile.write(json.dumps(mock_abilities).encode())
        elif self.path == "/api/v2/agents":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            # Return mock agents
            mock_agents = [
                {"paw": "mock-agent-1", "group": "red", "trusted": True, "sleep_min": 0}
            ]
            self.wfile.write(json.dumps(mock_agents).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path.startswith("/api/v2/abilities"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {"ability_id": "mock-created-ability"}
            self.wfile.write(json.dumps(response).encode())
        elif self.path.startswith("/api/v2/adversaries"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {"adversary_id": "mock-adversary"}
            self.wfile.write(json.dumps(response).encode())
        elif self.path.startswith("/api/v2/operations"):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {"id": "mock-operation"}
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress logging
        pass


def start_mock_server():
    """Start mock Caldera server"""
    # Bind to all interfaces so VMs can reach it
    server = HTTPServer(("0.0.0.0", 8888), CalderaMockHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(1)  # Give server time to start
    return server


if __name__ == "__main__":
    print("[caldera-mock] Starting mock Caldera server")
    server = start_mock_server()
    print("[caldera-mock] Mock Caldera running on http://localhost:8888")

    try:
        # Test API
        import urllib.request

        req = urllib.request.Request("http://localhost:8888/api/v2/abilities")
        req.add_header("KEY", "REDAPIKEY123")
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            print(f"[caldera-mock] API test: {len(data)} abilities available")

        print("[caldera-mock] Mock server ready for pipeline testing")

        # Keep running
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[caldera-mock] Stopping mock server")
        server.shutdown()
