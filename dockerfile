from ubuntu:latest

run apt-get update && apt-get install -y qemu-system-x86 qemu-kvm gcc-multilib make git

run git clone https://github.com/agantet/secos-ng

workdir /secos-ng

cmd ["/bin/sh"]