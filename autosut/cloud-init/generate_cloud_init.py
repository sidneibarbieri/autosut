#!/usr/bin/env python3
import textwrap
from pathlib import Path

cloud_init_dir = Path("cloud-init")
cloud_init_dir.mkdir(exist_ok=True)

pubkey_path = Path.home() / ".ssh/id_rsa.pub"
pubkey = pubkey_path.read_text().strip() if pubkey_path.exists() else ""

ssh_keys_block = (
    f"""
    ssh_authorized_keys:
      - {pubkey}"""
    if pubkey
    else ""
)

user_data = textwrap.dedent(f"""\
#cloud-config
hostname: sticks-arm
manage_etc_hosts: true
users:
  - default
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: ubuntu{ssh_keys_block}
ssh_pwauth: true
disable_root: false
chpasswd:
  list: |
    ubuntu:ubuntu
  expire: false
packages:
  - openssh-server
  - qemu-guest-agent
runcmd:
  - ssh-keygen -A
  - mkdir -p /etc/ssh/sshd_config.d
  - sh -c "printf 'PasswordAuthentication yes\\nPubkeyAuthentication yes\\nKbdInteractiveAuthentication no\\n' > /etc/ssh/sshd_config.d/99-cloud-lab.conf"
  - systemctl enable ssh
  - systemctl restart ssh
  - systemctl enable qemu-guest-agent
  - systemctl restart qemu-guest-agent
  - cloud-init status --wait || true
  - hostnamectl set-hostname sticks-arm
  - sh -c "echo cloud-init-complete > /var/tmp/cloud-init-complete"
""")

meta_data = """instance-id: sticks-001
local-hostname: sticks-arm
"""

(cloud_init_dir / "user-data").write_text(user_data)
(cloud_init_dir / "meta-data").write_text(meta_data)

snap_dir = Path("evidence/qemu-base")
snap_dir.mkdir(parents=True, exist_ok=True)
(snap_dir / "user-data.snapshot").write_text(user_data)
(snap_dir / "meta-data.snapshot").write_text(meta_data)

print("cloud-init files generated successfully")
