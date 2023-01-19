# NIKSS - Native In-Kernel P4-programmable Software Switch for Software-Defined Networking

[![build nikss](https://github.com/NIKSS-vSwitch/nikss/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/NIKSS-vSwitch/nikss/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**NIKSS** is an in-kernel implementation of a [P4](https://p4.org/) software switch. 
It works in conjunction with the [P4-eBPF](https://github.com/p4lang/p4c/tree/main/backends/ebpf/psa) compiler. 
The **NIKSS** switch uses [Portable Switch Architecture (PSA)](https://p4.org/p4-spec/docs/PSA.html) as a forwarding model and [extended Berkeley Packet Filter (eBPF)](https://ebpf.io/) as a packet processing engine. 
**NIKSS** works seamlessly with both TC-based and XDP-based flavors of the PSA model for the P4-eBPF compiler.

This repository implements a low-level C API and CLI tool (`nikss-ctl`) to manage P4/PSA programs for NIKSS. The PSA-eBPF compiler that is used to generate P4 programs for NIKSS sits in the [p4lang/p4c](https://github.com/p4lang/p4c/tree/main/backends/ebpf) repository.

Main features of NIKSS:
- **No additional dependencies** - NIKSS works on vanilla Linux OS and does not require any additional dependencies. We have tested NIKSS on Ubuntu 18+ and kernel version 5.8+.
- **P4 programmable** - the use of the P4 language allows to rapidly develop packet processing pipelines for end hosts.
- **Feature-rich programming model** - NIKSS leverages P4 Portable Switch Architecture that provides packet processing primitives needed to implement complex packet processing behaviors.
- **High performance** - NIKSS is meant to provide a high-performance P4 software switch due to the use of eBPF and TC/XDP hooks.

Refer to the ACM CoNEXT paper for more details on design and performance numbers: 

> Tomasz Osiński, Jan Palimąka, Mateusz Kossakowski, Frédéric Dang Tran, El-Fadel Bonfoh, and Halina Tarasiuk. 2022. "A novel programmable software datapath for Software-Defined Networking". In Proceedings of the 18th International Conference on emerging Networking EXperiments and Technologies (CoNEXT '22). Association for Computing Machinery, New York, NY, USA, 245–260. https://doi.org/10.1145/3555050.3569117

## Community

To discuss the NIKSS project you can use the following communication channels:
- Join the [P4 Slack](p4-lang.slack.com) and look for [#p4-ebpf](https://p4-lang.slack.com/archives/C039KK0MUAJ) channel.
- Feel free to [open a GitHub Issue](https://github.com/NIKSS-vSwitch/nikss/issues/new)!
- Join the mailing list: [nikss-vswitch](https://groups.google.com/g/nikss-vswitch)

# Installation

## Docker

You can build a Docker image for NIKSS by running the below command from the project's root directory:

```bash
docker build -t nikss:latest .
```

We also provide a stable Docker image that is built on CI. You can fetch it by:

```bash
docker pull osinstom/nikss:latest
```

## Installing NIKSS from source

### Dependencies

NIKSS depends on following libraries and utilities:
- GNU [make](https://www.gnu.org/software/make/)
- [CMake](https://cmake.org/)
- C compiler, GCC is tested
- [git](https://git-scm.com/) for version control
- GNU Multiple Precision Arithmetic Library [GMP](http://gmplib.org/)
- [libelf](https://sourceware.org/elfutils/)
- [zlib](http://zlib.net/)
- [Jansson](http://www.digip.org/jansson/)

All the dependencies can be installed on Ubuntu 20.04 with the following command:

```shell
sudo apt install make cmake gcc git libgmp-dev libelf-dev zlib1g-dev libjansson-dev
```

Note that `nikss-ctl` is statically linked with shipped `libbpf`, so there is no need to install this library
system-wide. It is a submodule for this repository.

### Build from source

1. Get the code with submodules:

   ```shell
   git clone --recursive https://github.com/NIKSS-vSwitch/nikss.git
   cd nikss
   ```

2. Build libbpf:

   ```shell
   ./build_libbpf.sh
   ```

3. Build the code and install binaries:

   ```shell
   mkdir build
   cd build
   cmake <CMAKE_OPTIONS> ..
   make -j4
   sudo make install
   ```
   
   Possible cmake options to customize build are listed in the table below:

   | CMake option | Possible values | Default value | Description |
   |--------------|-----------------|---------------|-------------|
   | `-DCMAKE_BUILD_TYPE` | empty \| `Release` \| `Debug` | empty | Build type. Empty means Debug without debug symbols. |
   | `-DCMAKE_INSTALL_PREFIX` | any path | `/usr/local` | Sets the directory where `make install` intall the binaries. |
   | `-DBUILD_SHARED` | `on` \| `off` | `off` | Build shared library. When disabled only the nikss-ctl is built. |

   Note on installing shared library: remember to execute `sudo ldconfig` after installation. If `libnikss` still can't
   be loaded, you can do one of these things:
   - Change prefix, e.g. to `/usr` and reinstall.
   - Add path to `LD_LIBRARY_PATH`, e.g.:
     ```shell
     export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
     ```
   - Add system-wide path for LD:
     ```shell
     echo "/usr/local/lib" > /etc/ld.so.conf.d/usr_local_lib.conf
     ldconfig
     ```

4. (Optional) Install C/C++ headers files:

   ```shell
   sudo make install_headers
   ```
   This step makes sense only when shared library is built (`BUILD_SHARED` is set to `on`) because otherwise linker will
   fail to find references to the `libnikss` library.

# Commands reference

*See [command reference](docs/command%20reference.md) for all the possible commands. Here listed only the most important ones.*

## Naming convention

All objects can be accessed by name  created by the `p4c` compiler. These names follow format `<pipeline>_<extern name>`.
For example so defined table and actions:

```p4
control ingress(/* ... */) {
    action a() {}
    action b() {}
    
    table example_table {
        key = { /* ... */ }
        actions = { NoAction; a1; a2; }
    }
    /* ... */
}
```

Table `example_table` can be accessed with name `ingress_example_table`, and action `a` with name `ingress_a`.
`NoAction` can be accessed with name `_NoAction` because it is not define within pipeline. In the same way names for all
other externs are created.

## Description of selected commands

Load pipeline into kernel bpf subsystem:
```shell
nikss-ctl pipeline load id <ID> <FILENAME>
```
- ID - unique ID of the pipeline, natural number.
- FILENAME - name of file with compiled PSA-eBPF programs.

---

Unload pipeline from kernel bpf subsystem:
```shell
nikss-ctl pipeline unload id <ID>
```
- ID - ID of the pipeline, natural number.

---

Attach port:
```shell
nikss-ctl add-port pipe <ID> dev <INTERFACE>
```
- ID - ID of the pipeline, natural number.
- INTERFACE - name of network interface to attach.

---

Detach port:
```shell
nikss-ctl del-port pipe <ID> dev <INTERFACE>
```
- ID - ID of the pipeline, natural number.
- INTERFACE - name of network interface to attach.

---

Show pipeline information:
```shell
nikss-ctl pipeline show id <ID>
```
- ID - ID of the pipeline, natural number.

---

Create clone session and add member to it:
```shell
nikss-ctl clone-session create pipe <ID> id <SESSION_ID>
nikss-ctl clone-session add-member pipe <ID> id <SESSION_ID> egress-port <OUTPUT_PORT> instance <INSTANCE_ID> [cos <CLASS_OF_SERVICE>] [truncate plen_bytes <BYTES>]
```
- ID - ID of the pipeline, natural number.
- SESSION_ID - unique ID of the session, natural number.
- OUTPUT_PORT - ifindex of the output port. Can be obtained from `ip link` command.
- INSTANCE_ID - instance ID. The same port can be added twice with different instance ID.
- CLASS_OF_SERVICE - class of service, value must be known to TC.
- BYTES - maximum length of the packet in bytes.

---

Create multicast group and add member to it:
```shell
nikss-ctl multicast-group create pipe <ID> id <MULTICAST_GROUP_ID>
nikss-ctl multicast-group add-member pipe <ID> id <MULTICAST_GROUP_ID> egress-port <OUTPUT_PORT> instance <INSTANCE_ID>
```
- ID - ID of the pipeline, natural number.
- MULTICAST_GROUP_ID - unique ID of the multicast group, natural number.
- OUTPUT_PORT - ifindex of the output port. Can be obtained from `ip link` command.
- INSTANCE_ID - instance ID. The same port can be added twice with different instance ID.

---

Add an entry to a table without implementation:
```shell
nikss-ctl table add pipe <ID> <TABLE> action <ACTION> key <KEY> data <DATA> [priority <PRIORITY>]
```
- ID - ID of the pipeline, natural number.
- TABLE - name of the table, with full path.
- ACTION - executed action. Can be specified by ID, e.g. `id 2` or by name, e.g. `name _NoAction`.
- KEY - list of table keys. Supported types for each key in the list:
   - exact - value, e.g. `2`.
   - lpm - value and prefix length separated by `/`, e.g. `192.168.1.0/24`
   - ternary - value and mask separated by `^`, e.g. `0x12^0xFF`
   - Each key can be written as IPv4 or MAC address, IPv6 is not supported yet. Values can be specified in binary, octal, decimal or hexadecimal format.
- DATA - list of action arguments. Each argument can be written as IPv4 or MAC address, IPv6 is not supported yet. Arguments can be specified in binary, octal, decimal or hexadecimal format.
- PRIORITY - value of priority. Higher value means higher priority.
