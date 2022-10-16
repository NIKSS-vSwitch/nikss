
from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info, error, debug

"""
This module is an extension of `mininet.node`. It provides Mininet objects for P4Host and NIKSS switch. 
"""

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


class NIKSSSwitch(Switch):
    """
    NIKSS switch. Requires nikss-ctl.
    """

    # Device ID is also used as a NIKSS pipeline ID.
    device_id = 0

    def __init__(self, name, bpf_path = None, device_id=None, **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert(bpf_path)

        self.bpf_path = bpf_path
        if device_id is not None:
            self.device_id = device_id
            NIKSSSwitch.device_id = max(NIKSSSwitch.device_id, device_id)
        else:
            self.device_id = NIKSSSwitch.device_id
            NIKSSSwitch.device_id += 1
        
    def start(self, controllers):
        info("Starting NIKSS switch {}.\n".format(self.name))
        self.cmd("nikss-ctl pipeline load id {} {}".format(self.device_id, self.bpf_path))

        for port, intf in self.intfs.items():
            if not "s1-" in str(intf):
                continue
            info("Attaching port {} to NIKSS switch {}.\n".format(intf, self.name))
            self.cmd("nikss-ctl add-port pipe {} dev {}".format(self.device_id, intf))


    def stop(self, deleteIntfs=True):
        for port, intf in self.intfs.items():
            if not "s1-" in str(intf):
                continue
            info("Detaching port {} from NIKSS switch {}.\n".format(intf, self.name))
            self.cmd("nikss-ctl del-port pipe {} dev {}".format(self.device_id, intf))
        self.cmd("nikss-ctl pipeline unload id {}".format(self.device_id))
        super( NIKSSSwitch, self ).stop( deleteIntfs )
