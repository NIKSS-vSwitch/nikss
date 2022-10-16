#!/usr/bin/env python3

import socket

from lib.nikss_mn import P4Host, NIKSSSwitch

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import SingleSwitchTopo

from time import sleep

class MyCustomTopo(Topo):

    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1',
                                bpf_path="simple_switch.o",
                                enable_tracing = True)
        for h in range(2):
            host = self.addHost('h%d' % (h + 1),
                                mac = '00:04:00:00:00:%02x' % (h + 1))
            self.addLink(host, switch, (h + 1), (h + 2))


def main():
    topo = MyCustomTopo()
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = NIKSSSwitch,
                  controller = None)
    net.start()

    sleep(1)

    h1 = net.get('h1')
    h1.setARP("10.0.0.2", "00:04:00:00:00:02")

    h2 = net.get('h2')
    h2.setARP("10.0.0.1", "00:04:00:00:00:01")

    s1 = net.get('s1')
    # Install table entries to forward traffic between hosts
    s1.cmd("nikss-ctl table add pipe 0 ingress_tbl_fwd id 1 key {} data {}".format(h2.MAC(), socket.if_nametoindex("s1-eth3")))
    s1.cmd("nikss-ctl table add pipe 0 ingress_tbl_fwd id 1 key {} data {}".format(h1.MAC(), socket.if_nametoindex("s1-eth2")))

    CLI( net )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
