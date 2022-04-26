#!/usr/bin/env python3

import socket


from lib.psabpf_mn import P4Host, PSAeBPFSwitch

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
                                bpf_path="out.o",
                                enable_tracing = True)
        for h in range(2):
            host = self.addHost('h%d' % (h + 1),
                                #ip = "10.0.%d.10/24" % h,
                                mac = '00:04:00:00:00:%02x' % (h + 1))
            self.addLink(host, switch, (h + 1), (h + 2))


def main():
    topo = MyCustomTopo()

    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = PSAeBPFSwitch,
                  controller = None)


    net.start()

    sleep(1)

    h1 = net.get('h1')
    h1.setARP("10.0.0.2", "00:04:00:00:00:02")

    h2 = net.get('h2')
    h2.setARP("10.0.0.1", "00:04:00:00:00:01")

    print(socket.if_nameindex())

    s1 = net.get('s1')
    s1.cmd("psabpf-ctl table add pipe 0 ingress_tbl_fwd id 1 key {} data {}".format(h2.MAC(), socket.if_nametoindex("s1-eth3")))
    s1.cmd("psabpf-ctl table add pipe 0 ingress_tbl_fwd id 1 key {} data {}".format(h1.MAC(), socket.if_nametoindex("s1-eth2")))

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
