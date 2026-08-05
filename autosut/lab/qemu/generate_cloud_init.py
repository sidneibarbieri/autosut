#!/usr/bin/env python3
"""Generate deterministic cloud-init files for QEMU Ubuntu ARM64."""

import shutil
from pathlib import Path

RUNTIME_DIR = Path(__file__).parent / "runtime"
EVIDENCE_DIR = Path(__file__).parent.parent.parent / "evidence" / "qemu-base"

USER_DATA_PATH = RUNTIME_DIR / "user-data"
META_DATA_PATH = RUNTIME_DIR / "meta-data"
USER_DATA_SNAPSHOT = EVIDENCE_DIR / "user-data.snapshot"
META_DATA_SNAPSHOT = EVIDENCE_DIR / "meta-data.snapshot"

PASSWORD_HASH = "$6$rounds=4096$saltysalt$z3X9kL8pQfX8vY2wR5tU7iO9pA1sD3fG5hJ7kM9nB2vC4xE6yF8gH0iJ2kL4mN6oP8qR"  # senha ubuntu

USER_DATA_TEMPLATE = """\
#cloud-config
hostname: sticks-arm
manage_etc_hosts: true

ssh_pwauth: true

users:
  - name: ubuntu
    passwd: {password_hash}
    lock_passwd: false
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL

chpasswd:
  list: |
    ubuntu:ubuntu
  expire: false

write_files:
  - path: /etc/ssh/sshd_config.d/99-cloud-lab.conf
    content: |
      PasswordAuthentication yes
      PubkeyAuthentication yes
      KbdInteractiveAuthentication no
      ChallengeResponseAuthentication no
    permissions: '0600'

runcmd:
  - echo "cloud-init running diagnostic" > /var/tmp/cloud-init-diagnostic.log
  - hostname > /var/tmp/hostname.txt
  - sshd -T | egrep 'passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication' >> /var/tmp/cloud-init-diagnostic.log || true
  - systemctl status ssh --no-pager >> /var/tmp/cloud-init-diagnostic.log || true
  - cat /etc/ssh/sshd_config.d/99-cloud-lab.conf >> /var/tmp/cloud-init-diagnostic.log || true
  - tail -n 50 /var/log/auth.log >> /var/tmp/cloud-init-diagnostic.log || true
  - touch /var/tmp/cloud-init-complete
  - echo "Diagnostic complete" >> /var/tmp/cloud-init-diagnostic.log

final_message: "The system is finally up, after $UPTIME seconds"
"""


def generate() -> None:
    user_data_content = USER_DATA_TEMPLATE.format(password_hash=PASSWORD_HASH)

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    USER_DATA_PATH.write_text(user_data_content, encoding="utf-8")
    META_DATA_PATH.write_text(
        "instance-id: qemu-lab\nlocal-hostname: sticks-arm\n", encoding="utf-8"
    )

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(USER_DATA_PATH, USER_DATA_SNAPSHOT)
    shutil.copy2(META_DATA_PATH, META_DATA_SNAPSHOT)

    print("cloud-init files generated successfully")


if __name__ == "__main__":
    generate()
