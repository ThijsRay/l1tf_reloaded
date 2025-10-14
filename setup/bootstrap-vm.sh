#!/usr/bin/env bash
# 
# Create a fresh Debian VM disk.
# Derived from syzkaller's create-image.sh script (Apache 2 lincense).

set -eux

# Variables affected by options
NAME=vm
SIZE=$((8 * 1024 - 1))
KERNEL=linux
RELEASE=stable
ARCH=$(uname -m)
PERF=false

# Display help function
display_help() {
    set +x
    echo "Usage: $0 [option...] " >&2
    echo "   -n, --name                 Name for the VM. Default: vm"
    echo "   -s, --size                 Disk size (GB). Default: 8 GB"
    echo "   -k, --kernel               Linux directory, from which to install kernel modules. Default: linux"
    echo "   -r, --release              Debian release. Default: stable"
    echo "   -a, --arch                 CPU architecture. Default: same as host"
    echo "   -p, --add-perf             Add perf support with this option enabled. Please set environment variable \$KERNEL at first"
    echo "   -h, --help                 Display help message"
    echo
    set -x
}

while true; do
    if [ $# -eq 0 ];then
	echo $#
	break
    fi
    case "$1" in
        -h | --help)
            display_help
            exit 0
            ;;
        -n | --name)
        NAME=$2
            shift 2
            ;;
        -s | --size)
        SIZE=$((1024 * $2 - 1))
            shift 2
            ;;
        -k | --kernel)
        KERNEL=$2
            shift 2
            ;;
        -a | --arch)
	    ARCH=$2
            shift 2
            ;;
        -r | --release)
	    RELEASE=$2
            shift 2
            ;;
        -p | --add-perf)
	    PERF=true
            shift 1
            ;;
        -*)
            echo "Error: Unknown option: $1" >&2
            exit 1
            ;;
        *)  # No more options
            break
            ;;
    esac
done

if [ ! -d $KERNEL ] || [ ! -d $KERNEL/drivers ] || [ ! -d $KERNEL/mm ]; then
    echo "Directory $KERNEL does not exist (or does not look like the Linux kernel source tree...)"
    exit 1
fi

# Create a minimal Debian distribution in a directory.
DIR="chroot-$NAME"
PKGS=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros,debian-ports-archive-keyring,make,tmux,git,cmake,libgmp3-dev,python3-pycryptodome,wget


# Handle cases where qemu and Debian use different arch names
case "$ARCH" in
    ppc64le)
        DEBARCH=ppc64el
        ;;
    aarch64)
        DEBARCH=arm64
        ;;
    arm)
        DEBARCH=armel
        ;;
    x86_64)
        DEBARCH=amd64
        ;;
    *)
        DEBARCH=$ARCH
        ;;
esac

# Foreign architecture

FOREIGN=false
if [ $ARCH != $(uname -m) ]; then
    # i386 on an x86_64 host is exempted, as we can run i386 binaries natively
    if [ $ARCH != "i386" -o $(uname -m) != "x86_64" ]; then
        FOREIGN=true
    fi
fi

if [ $FOREIGN = "true" ]; then
    # Check for according qemu static binary
    if ! which qemu-$ARCH-static; then
        echo "Please install qemu static binary for architecture $ARCH (package 'qemu-user-static' on Debian/Ubuntu/Fedora)"
        exit 1
    fi
    # Check for according binfmt entry
    if [ ! -r /proc/sys/fs/binfmt_misc/qemu-$ARCH ]; then
        echo "binfmt entry /proc/sys/fs/binfmt_misc/qemu-$ARCH does not exist"
        exit 1
    fi
fi

# Double check KERNEL when PERF is enabled
if [ $PERF = "true" ] && [ -z ${KERNEL+x} ]; then
    echo "Please set KERNEL environment variable when PERF is enabled"
    exit 1
fi

if [ -e $DIR ]; then
    echo "Directory/file $DIR already exists! Choose different VM name with '-n NAME'."
    exit 1
fi

sudo rm -rf $DIR
sudo mkdir -p $DIR
sudo chmod 0755 $DIR

# 1. debootstrap stage

DEBOOTSTRAP_PARAMS="--arch=$DEBARCH --include=$PKGS --components=main,contrib,non-free,non-free-firmware $RELEASE $DIR"
if [ $FOREIGN = "true" ]; then
    DEBOOTSTRAP_PARAMS="--foreign $DEBOOTSTRAP_PARAMS"
fi

# riscv64 is hosted in the debian-ports repository
# debian-ports doesn't include non-free, so we exclude firmware-atheros
if [ $DEBARCH == "riscv64" ]; then
    DEBOOTSTRAP_PARAMS="--keyring /usr/share/keyrings/debian-ports-archive-keyring.gpg --exclude firmware-atheros $DEBOOTSTRAP_PARAMS http://deb.debian.org/debian-ports"
fi
sudo --preserve-env=http_proxy,https_proxy,ftp_proxy,no_proxy debootstrap $DEBOOTSTRAP_PARAMS

# 2. debootstrap stage: only necessary if target != host architecture

if [ $FOREIGN = "true" ]; then
    sudo cp $(which qemu-$ARCH-static) $DIR/$(which qemu-$ARCH-static)
    sudo chroot $DIR /bin/bash -c "/debootstrap/debootstrap --second-stage"
fi

# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' $DIR/etc/passwd
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $DIR/etc/inittab
printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a $DIR/etc/network/interfaces
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo -en "127.0.0.1\tlocalhost\n" | sudo tee $DIR/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $DIR/etc/resolve.conf
echo "$NAME" | sudo tee $DIR/etc/hostname
ssh-keygen -f $NAME.id_rsa -t rsa -N ''
sudo mkdir -p $DIR/root/.ssh/
cat $NAME.id_rsa.pub | sudo tee $DIR/root/.ssh/authorized_keys

# Add perf support
if [ $PERF = "true" ]; then
    cp -r $KERNEL $DIR/tmp/
    BASENAME=$(basename $KERNEL)
    sudo chroot $DIR /bin/bash -c "apt-get update; apt-get install -y flex bison python-dev libelf-dev libunwind8-dev libaudit-dev libslang2-dev libperl-dev binutils-dev liblzma-dev libnuma-dev"
    sudo chroot $DIR /bin/bash -c "cd /tmp/$BASENAME/tools/perf/; make"
    sudo chroot $DIR /bin/bash -c "cp /tmp/$BASENAME/tools/perf/perf /usr/bin/"
    rm -r $DIR/tmp/$BASENAME
fi

# Install Linux kernel modules into the guest, and copy the kernel bz image
make -C $KERNEL -j `nproc`
sudo make -C $KERNEL modules_install -j `nproc` INSTALL_MOD_PATH=`pwd`/$DIR
cp $KERNEL/arch/x86/boot/bzImage $NAME.bz

# Add udev rules for custom drivers.
# Create a /dev/vim2m symlink for the device managed by the vim2m driver
echo 'ATTR{name}=="vim2m", SYMLINK+="vim2m"' | sudo tee -a $DIR/etc/udev/rules.d/50-udev-default.rules

# Build a disk image
dd if=/dev/zero of=$NAME.img bs=1M seek=$SIZE count=1
sudo mkfs.ext4 -F $NAME.img
sudo mkdir -p /mnt/$DIR
sudo mount -o loop $NAME.img /mnt/$DIR
sudo cp -a $DIR/. /mnt/$DIR/.
sudo umount /mnt/$DIR
