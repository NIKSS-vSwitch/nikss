
from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info, error, debug

class P4Host(Host):
    """
    P4Host is imported from p4_mininet.py (BMv2). 
    Disables VLAN offloading and sets eth0 as a default interface.
    """

    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print("**********")
        print(self.name)
        print("default interface: %s\t%s\t%s" %(
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()
        ))
        print("**********")

class PSAeBPFSwitch(Switch):
    """
    PSA-eBPF switch. Requires psabpf-ctl.
    """

    # Device ID is also used as a PSA-eBPF pipeline ID. 
    device_id = 0

    def __init__(self, name, bpf_path = None, enable_tracing = False, **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert(bpf_path)

        self.bpf_path = bpf_path

        
    def start(self, controllers):
        info("Starting PSA-eBPF switch {}.\n".format(self.name))
        self.cmd("psabpf-ctl pipeline load id {} {}".format(self.device_id, self.bpf_path), verbose=True)

        for port, intf in self.intfs.items():
            if not "s1-" in str(intf):
                continue
            info("Attaching port {} to PSA-eBPF switch {}.\n".format(intf, self.name))
            self.cmd("psabpf-ctl add-port pipe {} dev {}".format(self.device_id, intf), verbose=True)


    def stop(self, deleteIntfs=True):
        self.cmd("psabpf-ctl pipeline unload id {}".format(self.device_id), verbose=True)
        super( PSAeBPFSwitch, self ).stop( deleteIntfs )

    def attach(self, intf):
        info("Attaching port {} to PSA-eBPF switch {}.\n".format(intf, self.name))

    def detach(self, intf):
        info("Detaching port {} from PSA-eBPF switch {}.\n".format(intf, self.name))


