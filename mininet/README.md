# Using NIKSS with Mininet

This file explains how to use NIKSS with Mininet. To learn more about the PSA-eBPF compiler for NIKSS, please visit [the official documentation site](https://github.com/p4lang/p4c/tree/main/backends/ebpf/psa).

The `mininet/lib` directory contains a Python file (`nikss_mn.py`) that implements Mininet objects to run NIKSS in the Mininet environment. 
The Mininet objects are Python wrappers on top of the `nikss-ctl` tool.

**Note!** The NIKSS switch does not currently expose any remote control interface (such as P4Runtime or Thrift). The integration of NIKSS with a control plane software stack is 
still to be done. Hence, the Mininet wrappers use local the `nikss-ctl` commands to manage P4 programs.

## Writing Mininet script for NIKSS

Using Mininet to run NIKSS is as simple as using Python/Mininet objects in your script defining a Mininet topology. `demo.py` gives a basic example of how to define a Mininet topology composed of NIKSS switches.

## Demo

The `mininet/` directory contains a demonstration P4 program (`simple_switch.p4`) that implements a simple L2 forwarding and the demo Mininet topology defined in `demo.py`.

### Compile P4 program

In the first step, you must compile `simple_switch.p4` to eBPF bytecode. This guide assumes that you have `p4c-ebpf` with PSA extension already installed on your OS. 
To compile the P4 program, use the Make command provided by the eBPF backend of the P4 compiler (set `P4C_REPO` to the path of the `p4c/` root directory): 

```bash
make -f ${P4C_REPO}/backends/ebpf/runtime/kernel.mk BPFOBJ=simple_switch.o P4FILE=simple_switch.p4 ARGS="-DPSA_PORT_RECIRCULATE=2" P4ARGS="--Wdisable=unused" psa
```

The above command generates `simple_switch.o`, a BPF object file. 

### Run Mininet topology

Now, we can run a Mininet topology. The `demo.py` file defines a simple topology with one switch and two hosts attached to the switch. 

To create the network, execute the Python script:

```bash
sudo ./demo.py
```

You should see the Mininet CLI. 

### Configure NIKSS switch

Once you have the Mininet topology running, you can configure NIKSS switch(es). You can do it by:
- extending the Python script to install table entries automatically. The `demo.py` provides an example in lines 48-49, or
- manually executing `nikss-ctl` commands from Mininet CLI. For example, `s1 nikss-ctl table add ..` executes the `nikss-ctl` command on switch `s1`.

### Test demo setup

Run the below command to verify the connectivity between Mininet hosts:

```bash
mininet> h1 ping h2
```

## Support

The Mininet scripts are still experimental. Please report a bug, if you find one.
