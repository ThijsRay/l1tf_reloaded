#!/bin/bash

set -ue

echo "usage: $0 [VM name] [ssh port] [cpu affinity list]"
echo "Requires these file in current directory:"
echo "- [VM name].img     Disk (raw)"
echo "- [VM name].bz      Kernel (bzImage)"
VM_NAME=$1
SSH_PORT=$2
CPU_LIST=$3

# Add VM to SSH credentials.
echo ""
if [ ! -f ~/.ssh/config ]; then
	touch ~/.ssh/config
fi
if grep -q "Host $VM_NAME" ~/.ssh/config; then
	echo "$VM_NAME already in ssh config (but check port correctness)"
else
	echo "Adding $VM_NAME to ssh config"
	cat >> ~/.ssh/config<< EOF

Host $VM_NAME
     User root
     IdentityFile `pwd`/$VM_NAME.id_rsa
     Hostname localhost
     Port $SSH_PORT
EOF
fi
echo ""

# Boot the VM.
tmux new -s $VM_NAME -d "./_run-vm.sh $1 $2 $3"
sleep 1
if [ -f $VM_NAME.pid ]; then
	echo "VM is booting now on cpus $CPU_LIST!"
	echo "See boot terminal here:"
	echo "        tmux a -t $VM_NAME"
	echo "ssh access:"
	echo "        ssh $VM_NAME"
else
	echo "Failed to start up VM..."
	echo "Debug via ./_run-vm.sh $VM_NAME $SSH_PORT $CPU_LIST"
fi
