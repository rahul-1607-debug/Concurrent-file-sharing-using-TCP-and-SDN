"""Mininet topology: 1 OpenFlow switch, 1 file server, 3 clients.

        h2 (10.0.0.2) --\
        h3 (10.0.0.3) ---- s1 ---- h1 (10.0.0.1)  file server :9000
        h4 (10.0.0.4) --/            |
                                  Ryu controller (127.0.0.1:6633)

Run (second terminal, controller already started):  sudo python3 topology.py
"""
from functools import partial

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController


def main():
    net = Mininet(controller=None, link=TCLink,
                  switch=partial(OVSSwitch, protocols="OpenFlow13"))
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    s1 = net.addSwitch("s1")
    h1 = net.addHost("h1", ip="10.0.0.1/24")      # file server
    clients = [net.addHost(f"h{i}", ip=f"10.0.0.{i}/24") for i in (2, 3, 4)]
    net.addLink(h1, s1, bw=100)                    # 100 Mbps links
    for h in clients:
        net.addLink(h, s1, bw=100)
    net.start()
    print("\nStart the server:   h1 python3 server.py &")
    print("Client example:     h2 python3 client.py --host 10.0.0.1 -u bob -p bob123 list")
    print("Concurrency test:   h2 python3 test_concurrent.py --host 10.0.0.1 -n 3 --size 30\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
