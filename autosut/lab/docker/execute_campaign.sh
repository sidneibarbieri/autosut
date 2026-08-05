#!/bin/bash
# Campaign Execution Script for Docker Environment
# Executes MITRE campaigns in Docker containers

set -e

CAMPAIGN_ID=${1:-"C0001"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOFTWARE_DIR="$(dirname "$SCRIPT_DIR")/.."

echo "=== DOCKER CAMPAIGN EXECUTION ==="
echo "Campaign: $CAMPAIGN_ID"
echo "Software Dir: $SOFTWARE_DIR"

# Check Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running"
    exit 1
fi

# Build and start containers
echo "Starting campaign environment..."
cd "$SCRIPT_DIR"

# Build images
docker-compose build

# Start containers
docker-compose up -d

# Wait for containers to be ready
echo "Waiting for containers to be ready..."
sleep 10

# Check container status
echo "Checking container status..."
docker-compose ps

# Test connectivity
echo "Testing connectivity..."
docker-compose exec attacker ping -c 1 target || echo "⚠️  Network connectivity test failed"

# Test target services
echo "Testing target services..."
curl -s http://localhost:8080/vulnerable.php?cmd=whoami || echo "⚠️  Target web service test failed"

# Execute campaign
echo "Executing campaign $CAMPAIGN_ID..."
cd "$SOFTWARE_DIR"

# Set environment variables for Docker execution
export DOCKER_ENVIRONMENT=1
export TARGET_HOST=target
export ATTACKER_HOST=attacker

python3 scripts/run_campaign.py --campaign "$CAMPAIGN_ID"

# Collect artifacts
echo "Collecting artifacts..."
mkdir -p "$SOFTWARE_DIR/release/evidence/docker_artifacts"
docker cp campaign-target:/tmp/artifacts "$SOFTWARE_DIR/release/evidence/docker_artifacts/target/"
docker cp campaign-attacker:/tmp/artifacts "$SOFTWARE_DIR/release/evidence/docker_artifacts/attacker/"

echo "=== Campaign Execution Complete ==="
echo "Check release/evidence/ for execution results"
echo "Docker logs: docker-compose logs"
