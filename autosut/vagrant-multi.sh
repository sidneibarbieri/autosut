#!/bin/bash
# AutoSUT Multi-VM Vagrant interface for the QEMU sandbox.

case "$1" in
    "up")
        echo "Starting AutoSUT multi-VM sandbox..."
        python3 multi_vm_manager.py multi-up
        ;;
    "destroy"|"down")
        echo "Destroying AutoSUT sandbox..."
        python3 multi_vm_manager.py multi-down
        ;;
    "status")
        echo "AutoSUT sandbox status:"
        python3 multi_vm_manager.py multi-status
        ;;
    "ssh")
        shift
        if [ $# -eq 0 ]; then
            echo "Connecting to Caldera (C2)..."
            sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 8888 ubuntu@localhost
        elif [ "$1" = "attacker" ]; then
            echo "Connecting to attacker..."
            sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 ubuntu@localhost
        elif [ "$1" = "target-1" ]; then
            echo "Connecting to target-1..."
            sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2223 ubuntu@localhost
        elif [ "$1" = "target-2" ]; then
            echo "Connecting to target-2..."
            sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2224 ubuntu@localhost
        else
            echo "Executing on $1..."
            vm_name="$1"
            shift
            port="2222"
            case "$vm_name" in
                "caldera") port="8888" ;;
                "attacker") port="2222" ;;
                "target-1") port="2223" ;;
                "target-2") port="2224" ;;
            esac
            sshpass -p ubuntu ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$port" ubuntu@localhost "$@"
        fi
        ;;
    "provision")
        echo "Installing NGINX + PHP-FPM..."
        python3 nginx_manager.py install
        ;;
    "configure")
        if [ -z "$2" ]; then
            echo "Usage: $0 configure <campaign>"
            exit 1
        fi
        echo "Configuring campaign: $2"
        python3 nginx_manager.py configure "$2"
        ;;
    "campaign")
        if [ -z "$2" ]; then
            echo "Usage: $0 campaign <campaign_id>"
            exit 1
        fi
        echo "Starting AutoSUT campaign: $2"
        echo "Step 1: Starting VMs..."
        python3 multi_vm_manager.py multi-up
        echo "Step 2: Installing stack..."
        python3 nginx_manager.py install
        echo "Step 3: Configuring campaign..."
        python3 nginx_manager.py configure "$2"
        echo "Step 4: Applying SUT profile..."
        python3 src/apply_sut_profile.py --campaign="$2" --base-dir="."
        echo "Campaign $2 ready."
        echo ""
        echo "Access points:"
        echo "  Caldera (C2): http://localhost:8888"
        echo "  Attacker: vagrant ssh attacker"
        echo "  Target-1: vagrant ssh target-1"
        echo "  Target-2: vagrant ssh target-2"
        ;;
    *)
        echo "AutoSUT multi-VM sandbox commands:"
        echo "  up                    - Start all 4 VMs"
        echo "  down/destroy          - Stop all VMs"
        echo "  status                - Check VM status"
        echo "  ssh [vm] [cmd]        - Connect to VM (caldera|attacker|target-1|target-2)"
        echo "  provision             - Install NGINX + PHP-FPM"
        echo "  configure <campaign>  - Configure specific campaign"
        echo "  campaign <campaign>   - Full campaign setup"
        echo ""
        echo "Examples:"
        echo "  $0 up"
        echo "  $0 campaign shadowray"
        echo "  $0 ssh attacker 'hostname && whoami'"
        echo "  $0 ssh target-1 'curl localhost:8265'"
        exit 1
        ;;
esac
