#!/bin/bash
# Vagrant-like interface for QEMU ARM64 automation

case "$1" in
    "up")
        echo "Starting VM with automated QEMU..."
        python3 automate_qemu.py
        ;;
    "destroy"|"down")
        echo "Destroying VM..."
        pkill -f qemu-system-aarch64 || true
        rm -f vagrant-qemu.pid
        ;;
    "status")
        if pgrep -f qemu-system-aarch64 > /dev/null; then
            echo "VM is running"
            echo "SSH: sshpass -p ubuntu ssh -p 2222 ubuntu@localhost"
        else
            echo "VM is not running"
        fi
        ;;
    "ssh")
        shift
        if [ $# -eq 0 ]; then
            sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 ubuntu@localhost
        else
            sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 ubuntu@localhost "$@"
        fi
        ;;
    *)
        echo "Usage: $0 {up|down|destroy|status|ssh [command]}"
        exit 1
        ;;
esac
