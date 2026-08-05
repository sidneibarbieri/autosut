#!/usr/bin/env python3
"""Generate Vagrantfile from infra/topology.yaml"""

import yaml
from pathlib import Path

TOPLOGY_PATH = Path(__file__).parent.parent.parent / "infra" / "topology.yaml"
VAGRANTFILE_PATH = Path(__file__).parent.parent.parent / "infra" / "Vagrantfile"

def main():
    with open(TOPLOGY_PATH) as f:
        topo = yaml.safe_load(f)

    networks = topo["networks"]
    hosts = topo["hosts"]

    vagrantfile = f"""# -*- mode: ruby -*-
# vi: set ft=ruby :

# Auto-generated from infra/topology.yaml — DO NOT EDIT MANUALLY

Vagrant.configure("2") do |config|
"""

    # Define private networks
    for net in networks:
        vagrantfile += f"""
  config.vm.define "net-{net['name'].split('-')[-1]}" do |net_cfg|
    net_cfg.vm.network "private_network", type: "static", ip: "{net['cidr'].rsplit('.', 1)[0]}.1", virtualbox__intnet: "{net['name']}"
  end
"""

    # Define hosts
    for name, spec in hosts.items():
        vagrantfile += f"""
  config.vm.define "{name}" do |cfg|
    cfg.vm.box = "{spec['box']}"
    cfg.ssh.insert_key = false
"""

        # Assign IPs per network
        for net_name in spec["networks"]:
            ip = spec["ip"][net_name]
            vagrantfile += f'    cfg.vm.network "private_network", ip: "{ip}", virtualbox__intnet: "{net_name}"\n'

        # Provision role-specific scripts
        role = spec["role"]
        vagrantfile += f"""
    cfg.vm.provision "shell", inline: <<-SHELL
      echo 'role={role}' | sudo tee /etc/sticks-role
      hostnamectl set-hostname {name}
    SHELL
"""

        vagrantfile += "  end\n"

    vagrantfile += "\nend\n"

    VAGRANTFILE_PATH.write_text(vagrantfile)
    print(f"Generated {VAGRANTFILE_PATH}")

if __name__ == "__main__":
    main()
