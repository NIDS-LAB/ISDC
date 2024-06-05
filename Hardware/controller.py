import os
import sys
import glob
import scapy.all as scapy
import logging
import time
import queue
import threading
import crcmod
from scapy.pton_ntop import inet_pton
import ipaddress
import socket
from scapy.fields import *

bfrt_lib='{}/lib/python*/site-packages/tofino'.format(os.environ['SDE_INSTALL'])
sys.path.append(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 glob.glob(bfrt_lib)[0]))


from bfrt_grpc import client

global SRC_MAC

logging.basicConfig(filename='isdc.log', filemode='w', \
        format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
log = logging.getLogger("main")

lock_s=threading.Lock()
lock_a=threading.Lock()

class Report(scapy.Packet):
   name="Report"
   fields_desc = [ BitField("hash_", 0, 32),
                   BitField("seq", 0, 15),
                   BitField("ack", 0, 1)]

class SourceRoute(scapy.Packet):
   name="SourceRoute"
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 7)]

scapy.bind_layers(scapy.Ether, SourceRoute, type=0x1fbb)
scapy.bind_layers(SourceRoute, SourceRoute, bos=0)
scapy.bind_layers(SourceRoute, Report, bos=1)
scapy.bind_layers(scapy.IP, SourceRoute, proto=251)
scapy.bind_layers(scapy.IP, Report, proto=252)


class DigestIn:
    def __init__(self, client_, learn_filter):
        self.packet_in_queue = queue.Queue()
        self.client = client_
        self.learn_filter = learn_filter

        def _packet_in_recv_func(packet_in_queue):
            while True:
                msg = None
                try:
                    msg = self.client.digest_get()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    log.info("Polling for receiving digest - [%s]", e)
                if msg:
                    data_list = self.learn_filter.make_data_list(msg)
                    if  len(data_list) != 0:
                        data_dict = data_list[0].to_dict()
                        packet_in_queue.put(data_dict)

        self.recv_t = threading.Thread(target=_packet_in_recv_func, args=(self.packet_in_queue, ))
        self.recv_t.start()

    def sniff(self, function=None, timeout=None):
        msgs = []

        if timeout is not None and timeout < 0:
            raise ValueError("Timeout can't be a negative number.")

        if timeout is None:
            while True:
                try:
                    msgs.append(self.packet_in_queue.get(block=True))
                except Exception as e:
                    log.critical("Unexpected error retrieving digest from queue - [%s]", e)
                except KeyboardInterrupt:
                    break

        else:  # timeout parameter is provided
            deadline = time.time() + timeout
            remaining_time = timeout
            while remaining_time > 0:
                try:
                    msgs.append(self.packet_in_queue.get(block=True, timeout=remaining_time))
                    remaining_time = deadline - time.time()
                except KeyboardInterrupt:
                    break
                except queue.Empty:
                    # No item available on timeout. Exiting
                    break

        if function is None:
            return iter(msgs)
        else:
            for msg in msgs:
                function(msg)


class PacketIn:
    def __init__(self, iface_):
        self.packet_in_queue = queue.Queue()
        self.iface = iface_

        def _packet_in_recv_func(packet_in_queue):

            def _handle(pkt):
                if(pkt[scapy.Ether].src != SRC_MAC):
                    packet_in_queue.put(pkt)

            scapy.sniff(iface=self.iface, prn=_handle)

        self.recv_t = threading.Thread(target=_packet_in_recv_func, args=(self.packet_in_queue, ))
        self.recv_t.start()

    def sniff(self, function=None, timeout=None):
        msgs = []

        if timeout is not None and timeout < 0:
            raise ValueError("Timeout can't be a negative number.")

        if timeout is None:
            while True:
                try:
                    msgs.append(self.packet_in_queue.get(block=True))
                except Exception as e:
                    log.critical("Unexpected error retrieving packet-in from queue - [%s]", e)
                except KeyboardInterrupt:
                    break

        else:  # timeout parameter is provided
            deadline = time.time() + timeout
            remaining_time = timeout
            while remaining_time > 0:
                try:
                    msgs.append(self.packet_in_queue.get(block=True, timeout=remaining_time))
                    remaining_time = deadline - time.time()
                except KeyboardInterrupt:
                    # User sends an interrupt(e.g., Ctrl+C).
                    break
                except queue.Empty:
                    # No item available on timeout. Exiting
                    break

        if function is None:
            return iter(msgs)
        else:
            for msg in msgs:
                function(msg)

def extract_digest(msg):
    id_report=msg["flowid"]
    proto=msg["proto"]
    src=msg["src"]
    dst=msg["dst"]
    sport=msg["srcp"]
    dport=msg["dstp"]
    hval=msg["hval"]
    evic=msg["evic"]
    mf=msg["mf"]
    hval_=msg["hash"]
    cnt=msg["count"]
    bcnt=msg["bcount"]
    idx=msg["f_idx"]

    return id_report, proto, src, dst, sport, dport, hval, evic, mf, hval_, cnt, bcnt, idx

def get_swid(src, iplist):
    swid=-1
    for idx, item in enumerate(iplist):
        if ipaddress.ip_address(src) in ipaddress.ip_network(item):
            swid=idx
            break
    if(swid==-1):
        log.info("Src ip address not found.")
    return swid

def load_file(fname, num):
    with open(fname, "r") as f:
        poly=[]
        for i in range(num):
            l=f.readline()
            poly.append(l.strip())
    f.close()
    return poly

def con_retry(i, send_tab, ack_tab, iface_):

    TIMEOUT=720 
    MAX_RETRY=10 # Timout config

    while True:
        # making a deep copy
        lock_s.acquire()
        s_tab=copy.deepcopy(send_tab)
        lock_s.release()

    #    print("sw: %d, len(send): %d" %(i, len(s_tab)))
        resend=[]
        expire=[]
        T=time.time()
        cnt=0
        for key, value in s_tab.items(): # Identifying expired and resend items
            if(cnt<5 and (T - value[1]) > TIMEOUT and (value[3] < MAX_RETRY)):
                resend.append(key)
                cnt+=1
            if(value[3] > MAX_RETRY):
                expire.append(key)
        T=time.time()
        for key in resend:
            scapy.sendp(s_tab[key][2], iface=iface_)
        
        if(len(resend)>0 or len(expire)>0):
            lock_s.acquire()
            for key in resend:
                if(key in send_tab.keys()):
                    send_tab[key][1]=T
                    send_tab[key][3]+=1

            for key in expire:
                if(key in send_tab.keys()):
                    send_tab.pop(key)
            lock_s.release()


       # Removing expired item from ack table
        lock_a.acquire()
        a_tab=copy.deepcopy(ack_tab)
        lock_a.release()

        #print("sw: %d, len(ack): %d" %(i, len(a_tab)))
        expire=[]
        T=time.time()
        for key, value in a_tab.items():
            if((T - value[1])>TIMEOUT*MAX_RETRY):
                expire.append(key)

        if(len(expire)>0):
            lock_a.acquire()
            for key in expire:
                if(key in ack_tab.keys()):
                    ack_tab.pop(key)
            lock_a.release()

        time.sleep(5)

def reformat(pkt1):
    pkt=scapy.Ether(src=SRC_MAC, dst="ff:ff", type=0x1fbb)
    ip=None
    r=None
    for layer in pkt1.iterpayloads():
        if(layer.name=="IP"):
            ip=layer.copy()
            ip.remove_payload()
            ip.proto=252
        if(layer.name=="SourceRoute"):
            x=layer.copy()
            x.remove_payload()
            pkt/=x
        if(layer.name=="Report"):
            r=layer.copy()
            r.ack=1
            r.remove_payload()

    if(ip==None):
        print("Error in reformating!")
        return None

    return pkt/ip/r


def con_handle(i, in_, iface_, eh_list, ecnt_, ebcnt_, eswid_, ef_dist):

    send_table={}
    ack_table={}
    t=threading.Thread(target=con_retry, args=(i, send_table, ack_table, iface))
    t.start()

    while True:
        l=in_.get(block=True)
        pkt=l[1]   
        if(l[0]==1):  #just send
            scapy.sendp(pkt, iface=iface_)
            seq=pkt[Report].seq 
            lock_s.acquire()
            send_table[pkt[Report].hash_ + seq]=[seq, time.time(), pkt, 1]
            lock_s.release()

        elif(l[0]==0):
            if(pkt.haslayer(SourceRoute)==0 and pkt.haslayer(scapy.IP)==1 and pkt[scapy.IP].proto==252 and pkt[Report].ack==1):  #ack pkt
                h=pkt[Report].hash_
                seq=pkt[Report].seq
            
                lock_s.acquire()
                if((h + seq) in send_table.keys()):
                    if(send_table[(h + seq)][0] == seq):
                        send_table.pop((h + seq))
                else:
                    log.info("Ack and no entry!")
                lock_s.release()

            elif(pkt.haslayer(SourceRoute)==1):  #report info
                h=pkt[Report].hash_
                seq=pkt[Report].seq 
                seq_=-1
                pkt_a=None
                lock_a.acquire()
                if((h + seq) in ack_table.keys()):
                    seq_=ack_table[(h + seq)][0]
                    pkt_a=ack_table[(h + seq)][2]
                lock_a.release()
            
                if(seq_ == seq):
                    scapy.sendp(pkt_a, iface=iface_)

                else: # New info
                    new_pkt=reformat(pkt)
                    lock_a.acquire()
                    ack_table[(h + seq)]=[seq, time.time(), new_pkt]
                    lock_a.release()

                    scapy.sendp(new_pkt, iface=iface_)

                    data_=[int(x) for x in pkt.payload.load.decode('utf-8').split(",")]
                    eh_list.append(h)
                    ecnt_.append(data_[0])
                    ebcnt_.append(data_[1])
                    eswid_.append(data_[2])
                    #xtmp=data_[3:]
                    #ef_dist.append(xtmp)
            else:
                log.info("Unkown pkt!")
                pkt.show()

def init_queue_reg(info, target, size, qsize):
    reg_tab=info.table_get('Ingress.meter.reg_queue')
    indx=size
    for ii in range(qsize):
        reg_tab.entry_add(target, [reg_tab.make_key([client.KeyTuple('$REGISTER_INDEX', int(ii))])], \
                [reg_tab.make_data([client.DataTuple('Ingress.meter.reg_queue.f1', int(indx))])])
        indx+=1

def pull_flow_info(info, target, idx, bin_size):
    reg_tab=info.table_get('Egress.reg_grid')
    indx=idx*bin_size
    a=[]
    for i in range(bin_size):
        dx=reg_tab.entry_get(target, [reg_tab.make_key([client.KeyTuple('$REGISTER_INDEX', indx+i)])], {"from_hw": False})
        v=next(dx)[0].to_dict()["Egress.reg_grid.f1"]
        a.append(int(v))
        reg_tab.entry_add(target, [reg_tab.make_key([client.KeyTuple('$REGISTER_INDEX', indx+i)])], \
                [reg_tab.make_data([client.DataTuple('Egress.reg_grid.f1', 0)])])
    return a

def update_queue(info, target, l, qsize, prev):
        reg_tab=info.table_get('Ingress.meter.reg_cur_grid')
        reg_tab1=info.table_get('Ingress.meter.reg_queue')
        dx=reg_tab.entry_get(target, [reg_tab.make_key([client.KeyTuple('$REGISTER_INDEX', 0)])], {"from_hw": False})
        of=int(next(dx)[0].to_dict()["Ingress.meter.reg_cur_grid.f1"])
        if(of==prev):
            return of
        if (of > prev):
            for j in range(int(of - prev)):
                if(len(l)==0):
                    return (prev + j)
                x=l.pop()
                reg_tab1.entry_add(target, [reg_tab.make_key([client.KeyTuple('$REGISTER_INDEX', prev+j)])], \
                    [reg_tab.make_data([client.DataTuple('Ingress.meter.reg_queue.f1', x)])])
            return of
        if (prev > of):
            for j in range(int(qsize - prev)):
                if(len(l)==0):
                    return (prev + j)
                x=l.pop()
                reg_tab.entry_add(target, [reg_tab.make_key([client.KeyTuple('$REGISTER_INDEX', prev+j)])], \
                    [reg_tab.make_data([client.DataTuple('Ingress.meter.reg_queue.f1', x)])])
            return 0

if __name__ == '__main__':

    tuple5={}
    available_idx=set()
    PREV_OFFSET=0
    SWID=11 #Current Switch ID
    BIN=94 
    SIZE=2059*BIN
    QUEUE_S=256
    iplist=load_file("ips.txt", 2)
    global SRC_MAC
    SRC_MAC="00:02:00:00:03:00" #src MAC of exposed iface 
    iface="enp6s0" #iface for CPU_PORT com.
    #Data strcuture for localy measured flows
    h_list=[]
    cnt_=[]
    bcnt_=[]
    f_dist=[]

    #Data structure for reporting flows
    eh_list=[]
    ecnt_=[]
    ebcnt_=[]
    eswid_=[]
    ef_dist=[]

    GC=client.ClientInterface(grpc_addr="localhost:50052", client_id=1,device_id=0)
    bfrt_info=GC.bfrt_info_get(p4_name=None)
    GC.bind_pipeline_config(p4_name=bfrt_info.p4_name)

    log.info("Connected to program running '%s' \n"% bfrt_info.p4_name)

    target = client.Target()
    learn_filter = bfrt_info.learn_get("digest_a")


    dgin=DigestIn(GC, learn_filter)
    pktin=PacketIn(iface)

    log.info("Launched thread for packet-in/digest.")

    #Handling reliable reporting
    chan_queue=queue.Queue()
    thread=threading.Thread(target=con_handle, args=(SWID, chan_queue, iface, eh_list, ecnt_, ebcnt_, eswid_, ef_dist))
    thread.start()

    log.info("Initializing queue.")
    init_queue_reg(bfrt_info, target, SIZE/BIN, QUEUE_S)

    while True:
        digest_list=dgin.sniff(timeout=1)
        for msg in digest_list:
            id_report, proto, src, dst, sport, dport, hval, evic, mf, hval_, cnt, bcnt, pull_idx=extract_digest(msg)
            if(id_report==1): #FlowID collection
                if hval not in tuple5.keys():
                    tuple5[hval]=[proto, src, dst, sport, dport]
                    if(evic==0):
                        continue
            if(evic==1 and mf==0): #Eviction from FlowInspector TODO
                pass
            elif(evic==1 and mf==1): #FlowMeter eviction
                swid=get_swid(tuple5[hval_][1], iplist)
                if(swid==SWID): #No reporting needed
                    h_list.append(hval_)
                    cnt_.append(cnt)
                    bcnt_.append(bcnt)
                    xtmp=pull_flow_info(bfrt_info, target, pull_idx, BIN)
                    f_dist.append(xtmp)
                    available_idx.add(pull_idx)
                    PREV_OFFSET=update_queue(bfrt_info, target, available_idx, QUEUE_S, PREV_OFFSET)
                elif(swid!=-1): #Report pkt
                    xtmp=pull_flow_info(bfrt_info, target, pull_idx, BIN)
                    f_dist.append(xtmp)
                    available_idx.add(pull_idx)
                    PREV_OFFSET=update_queue(bfrt_info, target, available_idx, QUEUE_S, PREV_OFFSET)

                    #rehashing the calculated value with the edge switch's hash function if necessary
                    #h=hash_(tuple5[hval_][1], tuple5[hval_][2], tuple5[hval_][3], tuple5[hval_][4], tuple5[hval_][0], poly[swid]) 
                    data_=str(cnt)  + "," + str(bcnt) + "," + str(SWID)  + "," + ','.join([str(y) for y in xtmp])
                    src_=socket.inet_ntoa(int.to_bytes(tuple5[hval_][1], 4, 'big'))
                    dst_=socket.inet_ntoa(int.to_bytes(tuple5[hval_][2], 4, 'big'))
                    pkt=scapy.Ether(src=SRC_MAC, dst="ff:ff")/scapy.IP(dst=src_, src=dst_, proto=251)/Report(hash_=hval_, seq=(int(scapy.RandShort()) & int(0x7FFF)), ack=0)/scapy.Raw(data_)
                    chan_queue.put([1, pkt])

        packetin_list=pktin.sniff(timeout=2)
        for pkt in packetin_list:
            ip_pkt=pkt.payload
            chan_queue.put([0, ip_pkt])            
