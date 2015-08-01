from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
from collections import namedtuple
import os
import csv

log = core.getLogger()
FlowFile = "/pox/pox/misc/addflowpolicies.csv"

class AddFlow (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")
        # Our firewall table
        self.firewall = {}

    def sendRule (self, src, dst, pri, tp, action, dst_tp):
        """
        Drops this packet and optionally installs a flow to continue
        dropping similar ones for a while
        """

    	msg = of.ofp_flow_mod()
    	msg.priority = int(pri)
    	msg.match.dl_type = int(tp, 16)
#	match = of.ofp_match(dl_type = tp,
#                             nw_proto = pkt.ipv4.ICMP_PROTOCOL)
#    	msg.match.dl_src = "00:0c:29:50:dc:27"
    	msg.match.nw_dst = IPAddr(dst)
    	msg.match.nw_src = IPAddr(src)
    	msg.match.tp_dst = int(dst_tp)
    	msg.actions.append(of.ofp_action_output(port = int(action)))
    	self.connection.send(msg)



# function that allows adding firewall rules into the firewall table
    def AddRule (self, src=0, dst=0, pri=0, tp=0, action=0, dst_tp=0, value=True):
        if (src, dst, pri, tp, action, dst_tp) in self.firewall:
            log.info("Rule already present drop: src %s - dst %s", src, dst)
        else:
            log.info("Adding firewall rule drop: src %s - dst %s", src, dst)
            self.firewall[(src, dst, pri, tp, action, dst_tp)]=value
            self.sendRule(src, dst, pri, tp, action, dst_tp)

    # function that allows deleting firewall rules from the firewall table
    def DeleteRule (self, src=0, dst=0, pri=0, tp=0, action=0, dst_tp=0):
        try:
            del self.firewall[(src, dst, pri, tp, action, dst_tp)]
            sendRule(src, dst, pri, tp, action, dst_tp, 0)
            log.info("Deleting firewall rule drop: src %s - dst %s", src, dst)
        except KeyError:
            log.error("Cannot find in rule drop src %s - dst %s", src, dst)

    def _handle_ConnectionUp (self, event):
        ''' Add your logic here ... '''
        self.connection = event.connection

        ifile  = open(FlowFile, "rb")
        reader = csv.reader(ifile)
        rownum = 0
        for row in reader:
            # Save header row.
            if rownum == 0:
                header = row
            else:
                colnum = 0
                for col in row:
                    #print '%-8s: %s' % (header[colnum], col)
                    colnum += 1
                self.AddRule(row[1], row[2], row[3], row[4], row[5], row[6])
            rownum += 1
        ifile.close()

        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(AddFlow)
