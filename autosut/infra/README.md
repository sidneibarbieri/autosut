# STICKS Multi-Host Infrastructure

## Purpose
Provide a segmented, multi-host environment for realistic MITRE ATT&CK campaign execution with lateral movement and pivoting.

## Architecture
- Segment 1 (172.20.0.0/24): Caldera (C2) + Kali (attacker)
- Segment 2 (172.21.0.0/24): Nginx (pivot)
- Segment 3 (172.22.0.0/24): DB (target)

## Files
- `topology.yaml` — declarative network and host definition
- `Vagrantfile` — generated from topology (do not edit manually)
- `evidence/` — connectivity and campaign execution evidence

## Usage
1. Generate Vagrantfile: `python scripts/infra/generate_vagrantfile.py`
2. Bring up lab: `vagrant up`
3. Validate connectivity: `python scripts/validate/connectivity.py`
4. Run campaigns: `python scripts/campaigns/run.py <campaign-id>`
