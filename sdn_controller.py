"""Ryu OpenFlow 1.3 controller for the file-sharing network.

1. Learning switch (L2 forwarding).
2. Access policies for the file service (TCP port 9000):
      - BLOCKED_HOSTS     : not allowed to reach the file server (drop)
      - RATE_LIMITS_KBPS  : per-host bandwidth cap enforced with OpenFlow meters
3. Monitoring: every file-transfer TCP connection gets its own flow entry
   (5-tuple match), so flow statistics = per-transfer byte counters.
   Polled every POLL_SECONDS -> Mbps per connection and per client host.

Run:  ryu-manager sdn_controller.py
"""
import csv
import time
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                    DEAD_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
from ryu.ofproto import ofproto_v1_3

# ------------------------------ POLICY (edit me) ------------------------------
SERVER_IP = "10.0.0.1"
SERVICE_PORT = 9000
BLOCKED_HOSTS = {"10.0.0.4"}            # h4 may not use the file service
RATE_LIMITS_KBPS = {"10.0.0.3": 5000}   # h3 limited to 5 Mbps
POLL_SECONDS = 2
BW_LOG = "sdn_bandwidth.csv"
# -----------------------------------------------------------------------------

PRIO_BLOCK, PRIO_TRANSFER, PRIO_L2 = 200, 100, 1


class FileSharingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.mac_to_port = {}                 # dpid -> {mac: port}
        self.datapaths = {}
        self.meter_ids = {ip: i + 1 for i, ip in enumerate(RATE_LIMITS_KBPS)}
        self.prev = {}                        # flow key -> (bytes, time)
        with open(BW_LOG, "w", newline="") as f:
            csv.writer(f).writerow(["time", "client", "flow", "mbps"])
        self.monitor_thread = hub.spawn(self._monitor)

    # ------------------------------------------------------------ switch setup
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def on_switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp

        # table-miss: send unknown packets to the controller
        self._add_flow(dp, 0, p.OFPMatch(),
                       [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])

        # policy 1: block hosts from the file service (empty action list = drop)
        for ip in BLOCKED_HOSTS:
            m = p.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip,
                           ipv4_dst=SERVER_IP, tcp_dst=SERVICE_PORT)
            self._add_flow(dp, PRIO_BLOCK, m, [])
            self.logger.info("POLICY: dropping %s -> %s:%d", ip, SERVER_IP, SERVICE_PORT)

        # policy 2: create a meter per rate-limited host
        for ip, kbps in RATE_LIMITS_KBPS.items():
            band = p.OFPMeterBandDrop(rate=kbps, burst_size=0)
            dp.send_msg(p.OFPMeterMod(datapath=dp, command=ofp.OFPMC_ADD,
                                      flags=ofp.OFPMF_KBPS,
                                      meter_id=self.meter_ids[ip], bands=[band]))
            self.logger.info("POLICY: meter %d limits %s to %d kbps",
                             self.meter_ids[ip], ip, kbps)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def on_state_change(self, ev):
        if ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(ev.datapath.id, None)

    def _add_flow(self, dp, prio, match, actions, meter=None, idle=0):
        ofp, p = dp.ofproto, dp.ofproto_parser
        inst = []
        if meter:
            inst.append(p.OFPInstructionMeter(meter))
        inst.append(p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions))
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio, match=match,
                                 instructions=inst, idle_timeout=idle))

    # ---------------------------------------------------------- packet handling
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, p = dp.ofproto, dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            ip, t = pkt.get_protocol(ipv4.ipv4), pkt.get_protocol(tcp.tcp)
            if ip and t and SERVICE_PORT in (t.src_port, t.dst_port):
                # file-transfer connection: dedicated, metered, countable flow
                match = p.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=6,
                                   ipv4_src=ip.src, ipv4_dst=ip.dst,
                                   tcp_src=t.src_port, tcp_dst=t.dst_port)
                client = ip.src if ip.dst == SERVER_IP else ip.dst
                self._add_flow(dp, PRIO_TRANSFER, match, actions,
                               meter=self.meter_ids.get(client), idle=30)
            else:
                match = p.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
                self._add_flow(dp, PRIO_L2, match, actions, idle=60)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data))

    # --------------------------------------------------------------- monitoring
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL_SECONDS)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def on_flow_stats(self, ev):
        now = time.time()
        per_client = defaultdict(float)
        rows = []
        for st in ev.msg.body:
            m = st.match
            if st.priority != PRIO_TRANSFER or "tcp_dst" not in m:
                continue
            key = (ev.msg.datapath.id, m["ipv4_src"], m["tcp_src"],
                   m["ipv4_dst"], m["tcp_dst"])
            last = self.prev.get(key)
            self.prev[key] = (st.byte_count, now)
            if not last or now <= last[1]:
                continue
            mbps = (st.byte_count - last[0]) * 8 / (now - last[1]) / 1e6
            if mbps < 0.01:
                continue
            client = m["ipv4_src"] if m["ipv4_dst"] == SERVER_IP else m["ipv4_dst"]
            per_client[client] += mbps
            rows.append((client, f"{m['ipv4_src']}:{m['tcp_src']}->"
                                 f"{m['ipv4_dst']}:{m['tcp_dst']}", mbps))
        if rows:
            with open(BW_LOG, "a", newline="") as f:
                w = csv.writer(f)
                for client, flow, mbps in rows:
                    w.writerow([time.strftime("%H:%M:%S"), client, flow, f"{mbps:.2f}"])
            for c, v in sorted(per_client.items()):
                lim = RATE_LIMITS_KBPS.get(c)
                self.logger.info("BANDWIDTH client %-10s %8.2f Mbps%s", c, v,
                                 f"  (limit {lim/1000:.0f} Mbps)" if lim else "")
