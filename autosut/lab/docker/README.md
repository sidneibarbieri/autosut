# Docker Campaign Execution Environment

## Overview
Container-based environment for MITRE campaign execution on macOS.

## Architecture
- **Target Container**: Vulnerable Ubuntu system (Apache + PHP)
- **Attacker Container**: Ubuntu with attack tools
- **Network**: Isolated Docker bridge network
- **Storage**: Persistent volumes for artifacts

## Quick Start

### Prerequisites
- Docker Desktop for macOS
- Docker Compose (built-in)

### Setup and Execution
```bash
cd lab/docker

# Build and start containers
docker-compose up -d

# Execute campaign
./execute_campaign.sh C0001

# Check results
ls -la ../../release/evidence/
```

### Manual Execution
```bash
# Check container status
docker-compose ps

# Access containers
docker-compose exec attacker bash
docker-compose exec target bash

# View logs
docker-compose logs -f

# Stop environment
docker-compose down
```

## Container Details

### Target Container
- **Image**: Ubuntu 20.04
- **Services**: Apache2, PHP7.4, SSH
- **Vulnerabilities**:
  - Web shell at `/vulnerable.php`
  - Weak credentials (labuser:weakpass123)
- **Ports**: 8080 (HTTP), 2222 (SSH)

### Attacker Container
- **Image**: Ubuntu 20.04
- **Tools**: Python3, nmap, curl, wget, git
- **Purpose**: Execute attack techniques
- **Workspace**: `/workspace` (mounted to code directory)

## Network Configuration
- **Network**: `campaign-network` (172.20.0.0/16)
- **Target**: `target` (172.20.0.2)
- **Attacker**: `attacker` (172.20.0.3)

## Artifact Collection
- **Target artifacts**: `/tmp/artifacts` (inside container)
- **Attacker artifacts**: `/tmp/artifacts` (inside container)
- **Host collection**: `release/evidence/docker_artifacts/`

## Supported Techniques
- T1190: Exploit Public-Facing Application
- T1059.003: Unix Shell
- T1083: File and Directory Discovery
- T1041: Exfiltration Over C2 Channel

## Troubleshooting

### Docker Issues
```bash
# Check Docker status
docker info

# Restart Docker
# Use Docker Desktop application

# Check network
docker network ls
docker network inspect campaign-network
```

### Container Issues
```bash
# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Check logs
docker-compose logs target
docker-compose logs attacker
```

### Cleanup
```bash
# Stop and remove containers
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Remove network
docker network rm campaign-network
```

## Advantages over VMs
- **Faster startup**: Seconds vs minutes
- **Lower resource usage**: Less CPU/memory overhead
- **Easier cleanup**: Simple commands
- **Better reproducibility**: Immutable images
- **macOS compatible**: No virtualization issues

## Limitations
- **Shared kernel**: Less isolation than VMs
- **No KVM**: No hardware virtualization
- **Network simulation**: Limited network stack
- **Persistence**: Requires volume management

## Next Steps
1. Test with all campaigns (C0001-C0005)
2. Add more technique implementations
3. Improve artifact collection
4. Add monitoring and logging
5. Integrate with existing framework
