"""TO RUN:
    sudo mn --custom mytopo.py --topo mytopo --link tc
    """
from mininet.topo import Topo
   
class MyTopo(Topo):

    "Simple loop topology example."
 
    def __init__(self, **opts):
        "Create custom loop topo."
        
        # Initialize topology
        Topo.__init__(self, **opts)
        
        # Add hosts and switches
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        switch1 = self.addSwitch("s1")
        #switch2 = self.addSwitch("s2")
        #switch3 = self.addSwitch("s3")
        #switch4 = self.addSwitch("s4") 
        #switch5 = self.addSwitch("s5") 
        #IP setup
        #host2.setIP('10.1.2.2',24)
 
        # Add links
        # Ethernet Link
       # self.addLink(switch4, switch1, 1, 2, bw = 10, delay = '1ms', loss = 0)  
       # self.addLink(switch4, switch2, 2, 2, bw = 10, delay = '1ms', loss = 0) 
       # self.addLink(switch4, switch3, 3, 2, bw = 10, delay = '1ms', loss = 0)
       # self.addLink(switch4, host2, 4, bw = 10, delay = '1ms', loss = 0)
       # self.addLink(switch1, host1, 1, bw = 10, delay = '1ms', loss = 0)
       # self.addLink(switch5, host1, 1, bw = 10, delay = '1ms', loss = 0)
        self.addLink(switch1, host1, 1, bw = 10, delay = '1ms', loss = 0) 
        self.addLink(switch1, host2, 2, bw = 10, delay = '1ms', loss = 0 )
        #Wifi Link
       # self.addLink(switch2, host1, 1, bw = 2, delay = '5ms', loss = 3) 
        #3G Link
        #self.addLink(switch3, host1, 1, bw =2, delay = '75', loss = 2)

topos = {'mytopo': (lambda: MyTopo())}
