# L1TF Reloaded

This repository contains the proof-of-concept code for the *L1TF Reloaded* attack, as publicly disclosed during [WHY2025](https://program.why2025.org/why2025/talk/DG7VSX/).
It allows a malicious virtual machine to leak all physical memory of its host, including the memory of other virtual machines running on the system.
L1TF Reloaded combines two long-known transient execution vulnerabilities, [L1TF](https://foreshadowattack.eu/foreshadow-NG.pdf) and [(Half-)Spectre](https://spectreattack.com/spectre.pdf).
By combining them, commonly deployed software-based mitigations against L1TF, such as [L1d flushing](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1d_flush.html) and [core scheduling](https://www.man7.org/linux/man-pages/man1/coresched.1.html), can be circumvented.

We've demonstrated our attack on real-world KVM-based cloud solutions.
Both Google Cloud and AWS wrote a blog post in response to this attack, where they describe how they mitigate against L1TF Reloaded and how they harden their systems against unknown transient execution attacks.

- Google ["Project Rain:L1TF"](https://bughunters.google.com/blog/4684191115575296/project-Rain-L1tf) 
- AWS: ["Amazon EC2 defenses against L1TF Reloaded"](https://aws.amazon.com/blogs/security/ec2-defenses-against-l1tf-reloaded/)

More details can be found in our IEEE S&P 2026 paper ["Rain: Transiently Leaking Data from Public Clouds Using Old Vulnerabilities"](https://openreview.net/pdf?id=4tDNvQe2G0) and on our [project page](https://www.vusec.net/projects/rain/).

## Prerequisites

To run this in an attacker VM, make sure you have the following things setup:

- `CMake`, at least version 3.10.
- `make`
- `gcc`, we used version `gcc (GCC) 14.2.1 20240910`
- Headers for your guest Linux kernel, compiled with the patch in [setup/l1tf-pf.patch](setup/l1tf-pf.patch).

### Host Prerequisites

The specific gadgets that we leverage [have been patched in KVM](https://lore.kernel.org/kvm/20250804064405.4802-1-thijs@raymakers.nl/T/).
On Intel CPUs that are affected by L1TF, only stable kernel releases before 5.4.298, 5.10.242, 5.15.191, 6.1.150, 6.6.104, 6.12.45 or 6.16.5 are vulnerable to this specific attack.
The underlying issue is still there, but a different half-Spectre gadget is necessary to exploit L1TF Reloaded on up-to-date production systems.


## Demo

[![Demo video showing how we leak the private key from nginx running on a different guest on the same system](.github/thumbnail.png)](https://www.vusec.net/wp-content/uploads/2025/09/demo-gce-10s.webm)
## Running on Google Cloud
Note: since we've patched the gadgets, this no longer works as is on up to date host kernels.
However, these notes can be useful for setting up the attack on *your own infrastructure*. Only run this on infrastructure that you do have permission for!
Running it without permission of the infrastructure owner is most likely illegal in your jurisdiction.

### Setting up the VMs

Make sure you have a functioning Google Cloud account.

#### Create Sole-Tenant Node
- In the Google Compute Engine overview webpage, go to "Sole-tenant nodes".
- Click "Create node group", and:
  - Pick some "region" and "zone";
  - Create (or pick) a node template with:
    - "Node type" = n1-node-96-624; (Note: if not listed; pick another region/zone)
    - Enable "CPU overcommit".
  - Keep "Autoscaling" = off;
  - Pick "Number of nodes" = 1;
  - Keep the default maintenance and share settings.

#### Create Victim VM
- In the Google Compute Engine overview webpage, go to "Sole-tenant nodes".
- Pick (one of) your node group(s) based on a "n1-node-96-624" template.
- Click "create instance", and:
  - Set the "name", to e.g. `gce-victim`
  - Keep all other settings default, which means 2 vCPUs, 7.5 GB Memory, 10GB disk with Debian 12 Bookworm OS, etc.
  - "Create" the VM instance.
- Copy `setup/install_nginx_https.sh` script over to `gce-victim` and run it to install the Nginx webserver and configure it to HTTPS.
  The output should contain the private key of a newly generated, self-signed TLS certificate,
  and an example webpage containing "Welcome to nginx!".

#### Create Attacker VM

Create the `gce-attacker` VM via the Google Cloud Console,
similar to the victim VM, except for making its disk bigger: 50GB.
(We need some space to compile the Linux kernel.)

Install standard packages, download the L1TF Reloaded repo, and install a custom kernel that speeds up L1TF on `gce-attacker`:
```
sudo apt install -y locales-all fakeroot git kernel-wedge quilt ccache flex bison libssl-dev dh-exec rsync libelf-dev bc libncurses-dev lz4 liblz4-dev tmux cmake libgmp3-dev python3-pycryptodome
git clone git@github.com:ThijsRay/l1tf_reloaded.git
git clone git@github.com:torvalds/linux.git --branch v6.13 --depth 1
cd linux
git apply ../l1tf_reloaded/setup/l1tf-pf.patch
cp ../l1tf_reloaded/setup/kconfig .config
make -j2 bindeb-pkg
printf "\nGRUB_DISABLE_SUBMENU=y\n" | sudo tee -a /etc/default/grub
sudo dpkg -i ../linux-*.deb
```

Building the kernel takes almost 2 hours, so you might want to run it in the background in a tmux session.

Reboot the VM into the just installed `l1tf-pf` kernel (`sudo reboot`).
After reboot, ensure `uname -r` gives back `6.13.0-l1tf-pf+`.

If you want to run the exploit at scale, now would be a good moment to take a snapshot of the attacker VM,
such that you can spawn more instances of it, without the need for the two-hour long process above.

### The Exploit

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

## Licence

This is free software licensed under the European Union Public Licence v.1.2. See [LICENSE](./LICENSE) for more details.
