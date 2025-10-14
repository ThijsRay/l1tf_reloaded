#!/bin/bash

set -ue

VM_NAME=$1
SSH_PORT=$2
CPU_LIST=$3

sudo taskset -c $CPU_LIST \
	qemu-system-x86_64 \
		-cpu host,kvm=on \
		-smp sockets=1,cores=1,threads=2 \
		-m 8192 \
		-kernel $VM_NAME.bz \
		-append "root=/dev/sda net.ifnames=0 ro console=ttyS0" \
		-drive file=$VM_NAME.img,format=raw \
		-net user,hostfwd=tcp::$SSH_PORT-:22 -net nic \
		--enable-kvm \
		-nographic \
		-serial mon:stdio \
		-D /dev/stdout \
		-pidfile $VM_NAME.pid \
		-net nic -netdev tap,id=tap0 -device e1000,netdev=tap0 \
