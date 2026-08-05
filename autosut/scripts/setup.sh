#!/bin/bash
# setup.sh - Optional lab bootstrap for VM-backed development workflows

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[SETUP]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[SETUP]${NC} $1"; }
log_error() { echo -e "${RED}[SETUP]${NC} $1"; }
log_step() { echo -e "${BLUE}[SETUP]${NC} $1"; }

# Detect OS
OS=""
ARCH=""
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        ARCH=$(uname -m)
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        ARCH=$(uname -m)
    else
        log_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
    log_info "Detected OS: $OS ($ARCH)"
}

command_exists() {
    command -v "$1" &> /dev/null
}

install_python_deps() {
    log_step "Installing Python dependencies..."
    cd "$ROOT_DIR"

    if [[ -f "requirements-reviewer.txt" ]]; then
        pip3 install -q -r requirements-reviewer.txt 2>/dev/null || {
            pip3 install -q -r requirements-reviewer.txt --break-system-packages 2>/dev/null || true
        }
    fi

    python3 -c "import yaml" 2>/dev/null || {
        pip3 install -q pyyaml 2>/dev/null || pip3 install -q pyyaml --break-system-packages 2>/dev/null || true
    }

    log_info "OK Python dependencies installed"
}

install_virtualbox_macos() {
    log_step "Checking architecture..."

    if [[ "$ARCH" == "arm64" ]]; then
        log_warn "VirtualBox not supported on Apple Silicon (ARM64)"
        log_info "Installing QEMU provider for Vagrant instead..."
        install_qemu_macos
        return 0
    fi

    log_step "Installing VirtualBox for macOS..."

    if command_exists brew; then
        brew install --cask virtualbox 2>/dev/null || {
            log_warn "Homebrew failed, trying manual download..."
            install_virtualbox_macos_manual
        }
    else
        install_virtualbox_macos_manual
    fi
}

install_qemu_macos() {
    log_step "Installing QEMU provider for macOS ARM64..."

    # Install qemu via homebrew
    if command_exists brew; then
        brew install qemu 2>/dev/null || log_warn "QEMU install via brew failed"
    fi

    # Install vagrant-qemu plugin
    log_info "Installing vagrant-qemu plugin..."
    vagrant plugin install vagrant-qemu 2>/dev/null || {
        log_warn "vagrant-qemu plugin installation may require manual steps"
    }

    log_info "OK QEMU provider configured for ARM64"
}

install_virtualbox_macos_manual() {
    local vb_url="https://download.virtualbox.org/virtualbox/7.0.14/VirtualBox-7.0.14-161095-macOSArm64.dmg"
    if [[ "$ARCH" == "x86_64" ]]; then
        vb_url="https://download.virtualbox.org/virtualbox/7.0.14/VirtualBox-7.0.14-161095-macOSIntel.dmg"
    fi

    log_info "Downloading VirtualBox..."
    curl -L -o /tmp/virtualbox.dmg "$vb_url" 2>/dev/null || {
        log_error "Download failed. Install manually from https://www.virtualbox.org/"
        return 1
    }

    hdiutil attach /tmp/virtualbox.dmg -nobrowse 2>/dev/null || true
    sudo installer -pkg "/Volumes/VirtualBox/VirtualBox.pkg" -target / 2>/dev/null || true
    hdiutil detach "/Volumes/VirtualBox" 2>/dev/null || true
    rm -f /tmp/virtualbox.dmg
    log_info "OK VirtualBox installed"
}

install_vagrant_macos() {
    log_step "Installing Vagrant for macOS..."

    if command_exists brew; then
        brew install hashicorp/tap/hashicorp-vagrant 2>/dev/null || {
            install_vagrant_macos_manual
        }
    else
        install_vagrant_macos_manual
    fi
}

install_vagrant_macos_manual() {
    local vg_url="https://releases.hashicorp.com/vagrant/2.4.1/vagrant_2.4.1_darwin_arm64.dmg"
    if [[ "$ARCH" == "x86_64" ]]; then
        vg_url="https://releases.hashicorp.com/vagrant/2.4.1/vagrant_2.4.1_darwin_amd64.dmg"
    fi

    log_info "Downloading Vagrant..."
    curl -L -o /tmp/vagrant.dmg "$vg_url" 2>/dev/null || {
        log_error "Download failed. Install manually from https://www.vagrantup.com/"
        return 1
    }

    hdiutil attach /tmp/vagrant.dmg -nobrowse 2>/dev/null || true
    sudo installer -pkg "/Volumes/Vagrant/vagrant.pkg" -target / 2>/dev/null || true
    hdiutil detach "/Volumes/Vagrant" 2>/dev/null || true
    rm -f /tmp/vagrant.dmg
    log_info "OK Vagrant installed"
}

install_virtualbox_linux() {
    log_step "Installing VirtualBox for Linux..."

    if command_exists apt-get; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq virtualbox 2>/dev/null || {
            log_warn "apt install failed"
            return 1
        }
    elif command_exists dnf; then
        sudo dnf install -y virtualbox 2>/dev/null || {
            return 1
        }
    else
        log_warn "Unknown package manager. Install VirtualBox manually."
        return 1
    fi
    log_info "OK VirtualBox installed"
}

install_vagrant_linux() {
    log_step "Installing Vagrant for Linux..."

    if command_exists apt-get; then
        curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add - 2>/dev/null || true
        sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main" 2>/dev/null || true
        sudo apt-get update -qq
        sudo apt-get install -y -qq vagrant 2>/dev/null || {
            return 1
        }
    elif command_exists dnf; then
        sudo dnf install -y vagrant 2>/dev/null || {
            return 1
        }
    else
        log_warn "Unknown package manager. Install Vagrant manually."
        return 1
    fi
    log_info "OK Vagrant installed"
}

main() {
    echo ""
    echo "+==============================================================+"
    echo "|        STICKS Optional VM Lab Bootstrap                      |"
    echo "+==============================================================+"
    echo ""

    log_warn "This script prepares optional VM-backed lab helpers."
    log_warn "The canonical validation path remains bash artifact/setup.sh."

    detect_os

    # Python check (required)
    if ! command_exists python3; then
        log_error "Python3 required. Install from https://python.org/"
        exit 1
    fi
    log_info "OK Python3: $(python3 --version)"

    # Install Python deps
    install_python_deps

    # Install VirtualBox if missing
    if ! command_exists VBoxManage; then
        log_warn "VirtualBox not found. Auto-installing..."
        if [[ "$OS" == "macos" ]]; then
            install_virtualbox_macos || log_warn "VBox install failed"
        else
            install_virtualbox_linux || log_warn "VBox install failed"
        fi
    else
        log_info "OK VirtualBox: $(VBoxManage --version 2>/dev/null | head -1)"
    fi

    # Install Vagrant if missing
    if ! command_exists vagrant; then
        log_warn "Vagrant not found. Auto-installing..."
        if [[ "$OS" == "macos" ]]; then
            install_vagrant_macos || log_warn "Vagrant install failed"
        else
            install_vagrant_linux || log_warn "Vagrant install failed"
        fi
    else
        log_info "OK Vagrant: $(vagrant --version)"
    fi

    # Final verification
    echo ""
    local ready=true

    if ! command_exists python3; then
        log_error "FAIL Python3 missing"
        ready=false
    fi
    if ! command_exists vagrant; then
        log_error "FAIL Vagrant missing - install from https://www.vagrantup.com/"
        ready=false
    fi

    # Check for VirtualBox or QEMU (for ARM64)
    if [[ "$OS" == "macos" && "$ARCH" == "arm64" ]]; then
        if command_exists qemu-system-aarch64 || vagrant plugin list | grep -q vagrant-qemu; then
            log_info "OK QEMU provider available for ARM64"
        else
            log_error "FAIL QEMU provider missing"
            ready=false
        fi
    else
        if ! command_exists VBoxManage; then
            log_error "FAIL VirtualBox missing - install from https://www.virtualbox.org/"
            ready=false
        fi
    fi

    echo ""
    if [[ "$ready" == true ]]; then
        echo "+==============================================================+"
        echo "|              OK SETUP COMPLETE - READY TO USE                 |"
        echo "+==============================================================+"
        echo ""
        echo "Next: ./artifact.sh doctor"
        exit 0
    else
        echo "+==============================================================+"
        echo "|           FAIL SETUP INCOMPLETE - MANUAL INSTALL NEEDED         |"
        echo "+==============================================================+"
        exit 1
    fi
}

main "$@"
