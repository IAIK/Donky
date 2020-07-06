# Donky: Domain Keys – Efficient In-Process Isolation for RISC-V and x86

This repository contains the source code for the paper [Donky: Domain Keys – Efficient In-Process Isolation for RISC-V and x86](https://www.usenix.org/conference/usenixsecurity20/presentation/schrammel).

[Donky](https://www.usenix.org/conference/usenixsecurity20/presentation/schrammel) is an efficient hardware-software co-design for strong in-process isolation based on dynamic memory protection domains. The two main components are a secure software framework and a non-intrusive hardware extension. 

Disclaimer: The provided code is only a proof-of-concept. Use at your own risk. Note that the license only applies to `DonkyLib`, since the included submodules have separate licenses.

## Directory structure:

* DonkyLib: Contains the entire userspace library (Donky Monitor, API, self-tests).
* syscall_hook: Contains the Linux module required for x86 syscall filtering.
* sample_xml: Sample application using Donky to isolate xml parsing library TinyXML2.
* cva6: Hardware code for the modified Ariane/CVA6 RISC-V processor.
* ariane-sdk: Contains the tools for cross-compiling to RISC-V and running our library within the ISA simulator.

## Getting Started

This repository can be cloned using the following commands:
```
git clone git@github.com:IAIK/Donky.git
cd Donky
git submodule update --init --recursive
```

## Requirements

We have tested DonkyLib on Ubuntu 20.04 using the following packages:

```
sudo apt install build-essential clang autoconf automake autotools-dev curl libmpc-dev libmpfr-dev libgmp-dev libusb-1.0-0-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev device-tree-compiler pkg-config libexpat-dev python unzip
```

Furthermore, the following commands need be be executed in order to compile Donky for RISC-V.

```
mkdir toolchain
export RISCV=$(realpath toolchain)
export PATH=$PATH:$RISCV/bin
export SDKBASE=$(realpath ariane-sdk)/
```

## Building and running DonkyLib

Compile and run DonkyLib on x86 CPUs **without MPK**:
(Simulates memory protection keys. No security guarantees and isolation tests disabled.)

```
make -C DonkyLib PLATFORM=x86_64 RELEASE=1 TIMING=1 SIM=pk clean run
```

Compile and run DonkyLib on x86 CPUs **with MPK**:
```
make -C DonkyLib PLATFORM=x86_64 RELEASE=1 TIMING=1 clean run
```

The make flag `TIMING=1` also runs the integrated microbenchmarks, which can be omitted to only run self tests.
While omitting the `RELEASE=1` flag is also possible, it is not recommended since it's printing a lot of debug output. `TIMING=1` should only be used in conjunction with `RELEASE=1`.

### RISC-V

DonkyLib can also be compiled for RISC-V (by setting `PLATFORM=riscv`), but it requires the RISC-V compiler toolchain (in ariane-sdk), which takes a very long time to compile. This includes compiling RISC-V compilers, simulators, libc, Linux, and other dependencies. Building this will take several hours.

To build the RISC-V toolchain, run:

```
make -C ${SDKBASE} all
```

To run DonkyLib with the Proxykernel (not Linux) in the RISC-V ISA simulator, run:

```
make -C DonkyLib PLATFORM=riscv RELEASE=1 TIMING=1 SIM=pk clean run
```

The same can also be done using the real Linux kernel, but this will take a very long time to compile since it needs to download and build the Linux kernel:

```
make -C DonkyLib PLATFORM=riscv RELEASE=1 TIMING=1 clean run
```

Once Linux is booted in in the simulator, you can use `./x.elf` to run the binary.

## DonkyLib source code

Donky's source code can be found in the directory `DonkyLib`.
It is split into two parts: The trusted library resides in `pk`, while the untrusted code lies in `user`. Each of these also have `arch` subdirectories for architecture-specific code, since DonkyLib supports both x86_64 and RISC-V.
Donky API functions can be found in `pk/pk.h`. Its internal functions and metadata structures are defined in `pk/pk_internal.h`.
`user` contains all self-tests and the integrated micro-benchmarks. `main.c` contains the main function, which initializes DonkyLib and starts the integrated testsuite.

The Makefile compiles the trusted and untrusted part into seperate archives/sections, so that the library can protect its code and data. It can also be compiled into a shared library, which is used in `sample_xml` (see below).
By default, it compiles both the library and the user-side tests/benchmarks into a single executable: `x.elf`.


## sample_xml

The directory `sample_xml` contains a sample C++ application, which isolates TinyXML2 using DonkyLib.
This test first tests noraml xml parsing functionality when isolated usind DonkyLib.
Then it tests handling of exceptions within child-domains.
And finally it tests an artificial malicious function, which tries to access the stack of the parent, which should fail.

It can be run with the following commands:

For Intel CPUs **with MPK**:

```
make -C sample_xml clean run
```

For Intel CPUs **without MPK**:

```
make -C sample_xml SIM=pk clean run
```

Note, that access permissions cannot be enforced for CPUs without MPK.
