**This project is still a work in progress. We make no guarantee for the stability of the API or CLI and may modify
existing functions in the API or CLI.**

# Installation

## Dependencies

Psabpf depends on following libraries and utilities:
- GNU [make](https://www.gnu.org/software/make/)
- [CMake](https://cmake.org/)
- C compiler, GCC is tested
- [git](https://git-scm.com/) for version control
- [iproute2](https://wiki.linuxfoundation.org/networking/iproute2) (dependency might be removed in the future, see issue #1)
- GNU Multiple Precision Arithmetic Library [GMP](http://gmplib.org/)
- [libelf](https://sourceware.org/elfutils/)
- [zlib](http://zlib.net/)
- [Jansson](http://www.digip.org/jansson/)

All the dependencies can be installed on Ubuntu 20.04 with the following command:

```shell
sudo apt install iproute2 make cmake gcc git libgmp-dev libelf-dev zlib1g-dev libjansson-dev
```

Note that `psabpf-ctl` is statically linked with shipped `libbpf`, so there is no need to install this library
system-wide. It is a submodule for this repository.

## Installing psabpf from source

1. Get the code with submodules:

   ```shell
   git clone --recursive https://github.com/P4-Research/psabpf.git
   cd psabpf
   ```

2. Build libbpf:

   ```shell
   ./build_libbpf.sh
   ```

3. Build the code and install files:

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
   | `-DBUILD_SHARED` | `on` \| `off` | `off` | Build shared library. When disabled only the psabpf-ctl is built. |

   Note on installing shared library: remember to execute `sudo ldconfig` after installation. If `libpsabpf` still can't
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

# Command reference

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
psabpf-ctl pipeline load id <ID> <FILENAME>
```
- ID - unique ID of the pipeline, natural number.
- FILENAME - name of file with compiled PSA-eBPF programs.

---

Unload pipeline from kernel bpf subsystem:
```shell
psabpf-ctl pipeline unload id <ID>
```
- ID - ID of the pipeline, natural number.

---

Attach port:
```shell
psabpf-ctl add-port pipe <ID> dev <INTERFACE>
```
- ID - ID of the pipeline, natural number.
- INTERFACE - name of network interface to attach.

---

Detach port:
```shell
psabpf-ctl del-port pipe <ID> dev <INTERFACE>
```
- ID - ID of the pipeline, natural number.
- INTERFACE - name of network interface to attach.

---

Create clone session and add member to it:
```shell
psabpf-ctl clone-session create pipe <ID> id <SESSION_ID>
psabpf-ctl clone-session add-member pipe <ID> id <SESSION_ID> egress-port <OUTPUT_PORT> instance <INSTANCE_ID> [cos <CLASS_OF_SERVICE>] [truncate plen_bytes <BYTES>]
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
psabpf-ctl multicast-group create pipe <ID> id <MULTICAST_GROUP_ID>
psabpf-ctl multicast-group add-member pipe <ID> id <MULTICAST_GROUP_ID> egress-port <OUTPUT_PORT> instance <INSTANCE_ID>
```
- ID - ID of the pipeline, natural number.
- MULTICAST_GROUP_ID - unique ID of the multicast group, natural number.
- OUTPUT_PORT - ifindex of the output port. Can be obtained from `ip link` command.
- INSTANCE_ID - instance ID. The same port can be added twice with different instance ID.

---

Add an entry to a table without implementation:
```shell
psabpf-ctl table add pipe <ID> <TABLE> action <ACTION> key <KEY> data <DATA> [priority <PRIORITY>]
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
