# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  repo_root = File.expand_path(__dir__)
  runtime_dir = File.join(repo_root, "lab", "qemu", "runtime")

  config.vm.box = "sticks-simple"
  config.vm.box_version = "0"
  config.vm.box_check_update = false

  config.vm.hostname = "sticks-arm"
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.boot_timeout = 600

  # SSH com chave gerenciada pelo Vagrant
  config.ssh.username = "ubuntu"
  config.ssh.insert_key = true

  config.vm.provider "qemu" do |qe|
    qe.arch = "aarch64"
    qe.machine = "virt"
    qe.cpu = "cortex-a72"
    qe.memory = "4096"
    qe.smp = 4

    qe.networks = [{ type: "user", hostfwd: "tcp::2222-:22" }]

    qe.extra_args = [
      "-machine", "virt,accel=hvf",
      "-cpu", "cortex-a72",
      "-drive", "if=pflash,format=raw,file=/opt/homebrew/share/qemu/edk2-aarch64-code.fd,readonly=on",
      "-drive", "if=pflash,format=raw,file=#{File.join(runtime_dir, 'vars.fd')}",
      "-drive", "if=virtio,file=#{File.join(runtime_dir, 'run-overlay.qcow2')},format=qcow2,cache=none",
      "-drive", "if=virtio,file=#{File.join(runtime_dir, 'seed.iso')},media=cdrom"
    ]
  end
end
