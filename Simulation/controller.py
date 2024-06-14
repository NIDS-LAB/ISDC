#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import threading
from time import sleep
import time
import threading
import ipaddress
import crcmod
import copy
from queue import Queue
import queue
from scapy.pton_ntop import inet_pton
import scapy.all as scapy
from scapy.fields import *
from p4.v1 import p4runtime_pb2
from io import BytesIO
import binascii
import socket

import grpc

sys.path.append(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 './utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI as thrift

from p4runtime_lib.context import P4Type, Context
from p4runtime_lib.utils import UserError
from p4runtime_lib.P4object import PacketMetadata, P4Objects

MAX_32 = (1<<32) -1
TYPE_IPV4=0x800
TYPE_ACK = 3 + 0x8000
TYPE_RPT = 2 + 0x8000
TYPE_INFO = 0x88
PKT_INFO = 0x8888

class Info(scapy.Packet):
   name="Info"
   fields_desc = [ BitField("type_", 0, 8),
                   BitField("proto", 0, 8),
                   BitField("src", 0, 32),
                   BitField("dst", 0, 32),
                   BitField("sport", 0, 16),
                   BitField("dport", 0, 16),
                   BitField("hval", 0, 32),
                   BitField("evic", 0, 4),
                   BitField("mf", 0, 4),
                   BitField("hash", 0, 32),
                   BitField("cnt", 0, 32),
                   BitField("bcnt", 0, 32),
                   BitField("pf_idx", 0, 32),
                   BitField("h_idx", 0, 32),
                   BitField("nf_idx", 0, 32)]

class Report(scapy.Packet):
   name="Report"
   fields_desc = [ BitField("hash_", 0, 32),
                   BitField("seq", 0, 15),
                   BitField("ack", 0, 1)]

class SourceRoute(scapy.Packet):
   name="SourceRoute"
   fields_desc = [ BitField("bos", 0, 2),
                   BitField("port", 0, 14)]

scapy.bind_layers(scapy.Ether, Info, type=0x8888)
scapy.bind_layers(Info, SourceRoute, type_=0x88)
scapy.bind_layers(SourceRoute, SourceRoute, bos=0)
scapy.bind_layers(SourceRoute, scapy.IP, bos=1)



scapy.bind_layers(scapy.Ether, SourceRoute, type=0x1fbb)
scapy.bind_layers(SourceRoute, SourceRoute, bos=2)

scapy.bind_layers(scapy.Ether, SourceRoute, type=TYPE_RPT)
scapy.bind_layers(SourceRoute, Report, bos=3)
scapy.bind_layers(scapy.Ether, Report, type=TYPE_ACK)

class DigestIn:
    def __init__(self, client):
        self.packet_in_queue = Queue()

        def _packet_in_recv_func(packet_in_queue):
            while True:
                msg = client.get_stream_packet("digest", timeout=None)
                if not msg:
                    break
                packet_in_queue.put(msg)

        self.recv_t = threading.Thread(target=_packet_in_recv_func, args=(self.packet_in_queue, ))
        self.recv_t.start()

    def sniff(self, function=None, timeout=None):
        """
        Return an iterator of packet-in messages.
        If the function is provided, we do not return an iterator and instead we apply
        the function to every packet-in message.
        """
        msgs = []

        if timeout is not None and timeout < 0:
            raise ValueError("Timeout can't be a negative number.")

        if timeout is None:
            while True:
                try:
                    msgs.append(self.packet_in_queue.get(block=True))
                except KeyboardInterrupt:
                    # User sends a Ctrl+C -> breaking
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

class PacketIn:
    def __init__(self, client):
        self.packet_in_queue = Queue()

        def _packet_in_recv_func(packet_in_queue):
            while True:
                msg = client.get_stream_packet("packet", timeout=None)
                if not msg:
                    break
                packet_in_queue.put(msg)

        self.recv_t = threading.Thread(target=_packet_in_recv_func, args=(self.packet_in_queue, ))
        self.recv_t.start()

    def sniff(self, function=None, timeout=None):
        """
        Return an iterator of packet-in messages.
        If the function is provided, we do not return an iterator and instead we apply
        the function to every packet-in message.
        """
        msgs = []

        if timeout is not None and timeout < 0:
            raise ValueError("Timeout can't be a negative number.")

        if timeout is None:
            while True:
                try:
                    msgs.append(self.packet_in_queue.get(block=True))
                except KeyboardInterrupt:
                    # User sends a Ctrl+C -> breaking
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



class PacketOut:
    def __init__(self, client, context, payload=b'', **kwargs):

        self.p4_info = P4Objects(context, P4Type.controller_packet_metadata)["packet_out"]
        self.payload = payload
        self.metadata = PacketMetadata(self.p4_info.metadata)
        self.client=client
        if kwargs:
            for key, value in kwargs.items():
                self.metadata[key] = value

    def _update_msg(self):
        self._entry = p4runtime_pb2.PacketOut()
        self._entry.payload = self.payload
        self._entry.metadata.extend(self.metadata.values())

    def __setattr__(self, name, value):
        if name == "payload" and type(value) is not bytes:
            raise UserError("payload must be a bytes type")
        if name == "metadata" and type(value) is not PacketMetadata:
            raise UserError("metadata must be a PacketMetadata type")
        return super().__setattr__(name, value)

    def __dir__(self):
        return ["metadata", "send", "payload"]

    def __str__(self):
        self._update_msg()
        return str(_repr_pretty_p4runtime(self._entry))

    def _repr_pretty_(self, p, cycle):
        self._update_msg()
        p.text(_repr_pretty_p4runtime(self._entry))

    def send(self):
        self._update_msg()
        msg = p4runtime_pb2.StreamMessageRequest()
        msg.packet.CopyFrom(self._entry)
        self.client.requests_stream.put(msg)

def hash_(src, dst, sport, dport, proto, poly_):
    #src=int.from_bytes(scapy.pton_ntop.inet_pton(socket.AF_INET, src_), "big")
    #dst=int.from_bytes(scapy.pton_ntop.inet_pton(socket.AF_INET, dst_), "big")
    crc=src.to_bytes(4, 'big') +  dst.to_bytes(4, 'big') + proto.to_bytes(1, 'big') + sport.to_bytes(2, 'big') + dport.to_bytes(2, 'big')    
    poly_= poly_[:2] + "1" +  poly_[2:]
    pin=int(poly_, 16)
    f3 = crcmod.mkCrcFun(pin , xorOut=0, rev=True, initCrc=0)
    #f3 = crcmod.mkCrcFun(0x104c11db7, xorOut=0xFFFFFFFF, rev=True, initCrc=0)
    h3=f3(crc)

    return h3

def init_queue_reg(s, size, qsize):
    indx=size
    for ii in range(qsize):
        s.register_write("MyIngress.reg_queue", ii, indx)
        indx+=1
    for i in range(int(size)):
        s.register_write("MyIngress.Hflow_off", i, i)

def pull_flow_info(s, idx, bin_size):
    indx=idx*bin_size
    a=[]
    for i in range(bin_size):
        dx=s.register_read("MyIngress.reg_grid" , indx+i)
        a.append(int(dx))
        s.register_write("MyIngress.reg_grid" , indx+i, 0)
    return a

lock_idx=threading.Lock()
def update_queue(i, in_, qsize):
        s=thrift(9090+i)
        print("Listen on queue %d" %i)
        prev=0
        TT=0
        l=set()
        while True:
            X=in_.get(block=True)
            l.add(X)
            TT+=1
            for j in range(prev, prev + qsize, 1):
                val_=int(s.register_read("MyIngress.reg_queue", (j%qsize)))
                if(val_ == MAX_32):
                    if(len(l)==0):
                        break
                    x=l.pop()
                    s.register_write("MyIngress.reg_queue" , (j%qsize), x)
                    prev = (j+1)%qsize

def load_file(fname, num):
    with open(fname, "r") as f:
        poly=[]
        for i in range(num):
            l=f.readline()
            poly.append(l.strip())
    f.close()

    return poly

def extract_digest(msg):
    id_report=int.from_bytes(msg.data[0].struct.members[0].bitstring, 'big')
    proto=int.from_bytes(msg.data[0].struct.members[1].bitstring, 'big')
    src=int.from_bytes(msg.data[0].struct.members[2].bitstring, 'big')
    dst=int.from_bytes(msg.data[0].struct.members[3].bitstring, 'big')
    sport=int.from_bytes(msg.data[0].struct.members[4].bitstring, 'big')
    dport=int.from_bytes(msg.data[0].struct.members[5].bitstring, 'big')
    hval=int.from_bytes(msg.data[0].struct.members[6].bitstring, 'big')
    evic=int.from_bytes(msg.data[0].struct.members[7].bitstring, 'big')
    mf=int.from_bytes(msg.data[0].struct.members[8].bitstring, 'big')
    hval_=int.from_bytes(msg.data[0].struct.members[9].bitstring, 'big')
    cnt=int.from_bytes(msg.data[0].struct.members[10].bitstring, 'big')
    bcnt=int.from_bytes(msg.data[0].struct.members[11].bitstring, 'big')
    pull_idx=int.from_bytes(msg.data[0].struct.members[12].bitstring, 'big')
    h_idx=int.from_bytes(msg.data[0].struct.members[13].bitstring, 'big')
    nf_idx=int.from_bytes(msg.data[0].struct.members[14].bitstring, 'big')
 
    return id_report, proto, src, dst, sport, dport, hval, evic, mf, hval_, cnt, bcnt, pull_idx, h_idx, nf_idx

def get_swid(src, iplist):
    swid=-1
    for idx, item in enumerate(iplist):
        if ipaddress.ip_address(src) in ipaddress.ip_network(item):
            swid=idx
            break
    if(swid==-1):
        print("Src ip address not found")
    return swid

def reformat(pkt1):
    pkt=scapy.Ether(dst="ff:ff", type=0x1fbb)
    r=None
    for layer in pkt1.iterpayloads():
        if(layer.name=="SourceRoute"):
            x=layer.copy()
            x.remove_payload()
            if(x.bos == 1):
                x.bos=3
            pkt/=x
        if(layer.name=="Report"):
            r=layer.copy()
            r.ack=1
            r.remove_payload()
    return pkt/r

lock_p=threading.Lock()
lock_s=threading.Lock()
lock_a=threading.Lock()
lock_exp=threading.Lock()
lock_flow=threading.Lock()
lock_pkt=threading.Lock()
lock_tuple=threading.Lock()

def send_pkt(sw, context, pkt):
    lock_p.acquire()
    pktout=PacketOut(sw, context)
    pktout.payload = bytes(pkt)
    pktout.metadata['egress_port'] = '2'
    pktout.send()
    lock_p.release()

def con_retry(i, send_tab, ack_tab, sw, context):

    TIMEOUT=1800
    MAX_RETRY=10

    while True:
        lock_s.acquire()
        s_tab=copy.deepcopy(send_tab)
        lock_s.release()
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
            send_pkt(sw, context, s_tab[key][2])
        
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


def con_handle(i, in_, sw, context, eh_list, ecnt_, ebcnt_, eswid_, ef_dist):

    send_table={}
    ack_table={}
    t=threading.Thread(target=con_retry, args=(i, send_table, ack_table, sw, context))
    t.start()

    while True:
        l=in_.get(block=True)
        pkt=l[1]   
        if(l[0]==1):  #just send
            send_pkt(sw, context, pkt)
            seq=pkt[Report].seq 
            lock_s.acquire()
            send_table[pkt[Report].hash_ + seq]=[seq, time.time(), pkt, 1]
            lock_s.release()

        elif(l[0]==0):
            #if(pkt.haslayer(SourceRoute)==0 and pkt.haslayer(scapy.IP)==1 and pkt[scapy.IP].proto==252 and pkt[Report].ack==1):  #ack pkt
            if(pkt[scapy.Ether].type == TYPE_ACK):  #ack pkt
                h=pkt[Report].hash_
                seq=pkt[Report].seq

                lock_s.acquire()
                if((h + seq) in send_table.keys()):
                    if(send_table[(h + seq)][0] == seq):
                        send_table.pop((h + seq))
                else:
                    pass
                lock_s.release()


            elif(pkt[scapy.Ether].type == TYPE_RPT):  #report info

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
                    send_pkt(sw, context, pkt_a)

                else: # New info
                    new_pkt=reformat(pkt)
                    lock_a.acquire()
                    ack_table[(h + seq)]=[seq, time.time(), new_pkt]
                    lock_a.release()

                    send_pkt(sw, context, new_pkt)

                    data_=[int(x) for x in pkt.payload.load.decode('utf-8').split(",")]
                    eh_list.append(h)
                    ecnt_.append(data_[0])
                    ebcnt_.append(data_[1])
                    eswid_.append(data_[2])
                    xtmp=data_[3:]
                    ef_dist.append(xtmp)
            else:
                #print("Unknown packet")
                #pkt.show()
                pass

def get_lock(i, s, table, h_, idx, wr, p_idx):

    if(wr==False):
        ttl=int(s.register_read("MyIngress.path_reg", idx))
        s.register_write("MyIngress.path_reg", idx, 255)
        h=int(s.register_read(table , idx))
        if(h != h_):
            s.register_write("MyIngress.path_reg", idx, ttl)
            return False
    if(wr==True): 
        s.register_write("MyIngress.packet_cnt", idx, 0)    
        s.register_write("MyIngress.Hflow_off", idx, p_idx)
    return True;

def get_reg_cnt(s, idx):
       cnt=int(s.register_read("MyIngress.packet_cnt" , idx))
       bcnt=int(s.register_read("MyIngress.packet_bcnt" , idx))
       return cnt, bcnt


def get_data_and_send(i, bin_size, chan_queue, in_):
    s=thrift(9090+i)
    while True:
        l=in_.get(block=True)
        idx=l[0]
        data=l[1]
        pkt=l[2]
        h_idx=l[3]
        indx=idx*bin_size
        a=[]
        for j in range(bin_size):
            dx=s.register_read("MyIngress.reg_grid" , indx+j)
            a.append(int(dx))
            s.register_write("MyIngress.reg_grid" , indx+j, 0)

        if(h_idx!=-1):
            s.register_write("MyIngress.packet_cnt" , h_idx, 0)    
            s.register_write("MyIngress.Hflow_off", h_idx, idx)
        data_=data + ','.join([str(y) for y in a])
        pkt=pkt/scapy.Raw(data_)
        chan_queue.put([1, pkt])

def report_expire(i, in_, chan_queue, tuple5, iplist, BIN, poly):

    t_queue=[Queue(), Queue(), Queue(), Queue()]
    thread=[]
    for j in range(len(t_queue)):
        tu=threading.Thread(target=get_data_and_send, args=(i, BIN, chan_queue, t_queue[j]))
        tu.start()

    s=thrift(9090+i)
    print("Listen reporter: %d" %(i))
    X=0
    while True:
        l=in_.get(block=True)
        try:
            swid=get_swid(tuple5[l[1]][1], iplist)
        except:
            in_.put(l)
            time.sleep(1)
            continue
        if(swid!=-1):
            if(l[0] == 2): #Garbage Collection
               if(get_lock(i, s, "MyIngress.hash_check_register", l[1], l[4], False, 0) == False):
                    continue
               cnt, bcnt=get_reg_cnt(s, l[4]) 
               p_idx=l[5]
            h=hash_(tuple5[l[1]][1], tuple5[l[1]][2], tuple5[l[1]][3], tuple5[l[1]][4], tuple5[l[1]][0], poly[swid])
            src_port = tuple5[l[1]][5]
            lst=src_port.lastlayer()
            lst.bos=2
            
            data_=str(cnt)  + "," + str(bcnt) + "," + str(i) + "," #+ ','.join([str(y) for y in xtmp])
            pkt=scapy.Ether(dst="ff:ff", type=0x1fbb)/src_port/Report(hash_=h, seq=(int(scapy.RandShort()) & int(0x7FFF)), ack=0)
            t_queue[X%4].put([p_idx, data_, pkt, l[4]])
            X+=1
        else:
            # uknown cases
            pass


def get_data(i, arr, bin_size, in_):
    s=thrift(9090+i)
    while True:
        l=in_.get(block=True)
        idx=l[1]
        index=l[0]
        h_idx=l[2] 
        indx=idx*bin_size
        a=[]
        for j in range(bin_size):
            dx=s.register_read("MyIngress.reg_grid" , indx+j)
            a.append(int(dx))
            s.register_write("MyIngress.reg_grid" , indx+j, 0)
        if(h_idx!=-1):
            s.register_write("MyIngress.packet_cnt" , h_idx, 0)    
            s.register_write("MyIngress.Hflow_off", h_idx, idx)
        arr[index]=a

def storage(i, in_, h_list, cnt_, bcnt_, type_, swid_, f_dist, BIN):

    s=thrift(9090+i)
    X=0
    t_queue=[Queue(), Queue(), Queue(), Queue()]
    thread=[]
    for j in range(len(t_queue)):
        tu=threading.Thread(target=get_data, args=(i, f_dist, BIN, t_queue[j]))
        tu.start()

    while True:
        l=in_.get(block=True)
        if(l[0] == 0):
            h_list.append(l[1])
            cnt_.append(l[2])
            bcnt_.append(l[3])
            type_.append(1)
            swid_.append(i)
            f_dist.append([0]*BIN)
        elif(l[0] == 2):
            if(get_lock(i, s, "MyIngress.hash_check_register", l[1], l[4], False, 0) == False):
                continue
            cnt, bcnt=get_reg_cnt(s, l[4]) 
            p_idx=l[5]
            h_list.append(l[1])
            cnt_.append(cnt)
            bcnt_.append(bcnt)
            type_.append(2)
            swid_.append(i)
            f_dist.append([])
            t_queue[X%4].put([len(f_dist)-1, p_idx, l[4]])
            X+=1
        else:
            # uknown cases
            pass


pause_event = threading.Event()
resume_event = threading.Event()
def garbage_collector(i, in_, flow_rep, flow_loc):
    print("Listen collector: %d" %(i))

    f_track={}
    f_q=[]
    TIMEOUT=int(15)
    P=0
    while True:
        l=None
        if pause_event.is_set():
            XX=time.time()
            print("Garbage Collector is paused. Waiting for resume signal.")
            resume_event.wait()
            P+=(time.time() - XX)
        try:
            l=in_.get(timeout=7)
        except queue.Empty:
            pass
        if(l!=None):
            if(l[0] == 0):
                if(l[4] == MAX_32):
                    print("Error: confflict for flows: %d %d (%d)" %(l[3], l[4], i))
                else:
                    if(l[1] not in f_track):
                        f_track[l[1]]=[l[3], l[4], l[2], l[5]]
                        f_q.append((l[1], l[2]))
            elif(l[0] == 1):
                if(l[1] in f_track):
                    f_q.remove((l[1], f_track[l[1]][2]))
                    f_track.pop(l[1])

        for v in f_q:
            if(((time.time()-P) - v[1]) > TIMEOUT):
                if(f_track[v[0]][3]==0): #deligated flow
                    flow_rep.put([2, v[0], 0, 0, f_track[v[0]][0], f_track[v[0]][1]])
                elif(f_track[v[0]][3]==1): #local flow
                    flow_loc.put([2, v[0], 0, 0, f_track[v[0]][0], f_track[v[0]][1]])


                f_track.pop(v[0])
                f_q.remove(v)
            else:
                break

def PktIn(i, pktin, chan_queue, flow_evict, exp_q, tuple5):

    DD=0
    while True:
        packetin_list=pktin.sniff(timeout=5)
        for pkt in packetin_list:
            eth=scapy.Ether(pkt.packet.payload)
            if(eth.haslayer(scapy.Ether)==0):
                print("Error!")
                eth.show()
                continue
            if(eth.type == TYPE_RPT or eth.type == TYPE_ACK):
                chan_queue.put([0, eth])            
            elif(eth.type == PKT_INFO):

                if(eth[Info].hval not in tuple5):
                    tuple5[eth[Info].hval]=[eth[Info].proto, eth[Info].src, eth[Info].dst, eth[Info].sport, eth[Info].dport, eth[Info].payload]
                exp_q.put([0, eth[Info].hval, time.time(), eth[Info].h_idx, eth[Info].nf_idx, 0])
                if(eth[Info].evic==1 and eth[Info].mf==1):
                    if(i==2):
                        DD+=1
                        if(DD%100==0):
                            print("pkin: ", DD)
                    flow_evict.put([1, eth[Info].hash, eth[Info].cnt, eth[Info].bcnt, eth[Info].pf_idx])
                    exp_q.put([1, eth[Info].hash])

def evict_and_send(i, bin_size, available_idx, chan_queue, in_):

    s=thrift(9090+i)
    while True:
        l=in_.get(block=True)
        idx=l[0]
        data=l[1]
        pkt=l[2]
        indx=idx*bin_size
        a=[]
        for j in range(bin_size):
            dx=s.register_read("MyIngress.reg_grid" , indx+j)
            a.append(int(dx))
            s.register_write("MyIngress.reg_grid" , indx+j, 0)

        available_idx.put(idx)
        data_=data + ','.join([str(y) for y in a])
        pkt=pkt/scapy.Raw(data_)
        chan_queue.put([1, pkt])

def eviction(i, in_, chan_queue, available_idx, BIN, tuple5, poly, iplist):

    t_queue=[Queue(), Queue(), Queue(), Queue()]
    thread=[]
    for j in range(len(t_queue)):
        tu=threading.Thread(target=evict_and_send, args=(i, BIN, available_idx, chan_queue, t_queue[j]))
        tu.start()
    X=0
    while True:
        l=in_.get(block=True)
        try:
            swid=get_swid(tuple5[l[1]][1], iplist)
        except:
            in_.put(l)
            time.sleep(1)
            continue
        if(l[0] == 1): #Eviction
            cnt=l[2]
            bcnt=l[3]
            p_idx=l[4]

            h=hash_(tuple5[l[1]][1], tuple5[l[1]][2], tuple5[l[1]][3], tuple5[l[1]][4], tuple5[l[1]][0], poly[swid])
            src_port = tuple5[l[1]][5]
            lst=src_port.lastlayer()
            lst.bos=2
            
            data_=str(cnt)  + "," + str(bcnt) + "," + str(i) + "," #+ ','.join([str(y) for y in xtmp])
            pkt=scapy.Ether(dst="ff:ff", type=0x1fbb)/src_port/Report(hash_=h, seq=(int(scapy.RandShort()) & int(0x7FFF)), ack=0)
            t_queue[X%4].put([p_idx, data_, pkt])
            X+=1
        else:
            # uknown cases
            pass

def controller(i, p4info_helper, sw, context, h_list, cnt_, bcnt_, type_, swid_, poly, u_tuple , eh_list, ecnt_, ebcnt_, eswid_, ef_dist, f_dist):
    DIGEST_ID = 386821644 # digest id in the p4info file 
    BIN=94 
    SIZE=9287*BIN
    QUEUE_S=2048
    u_tuple.append(0)
    tuple5={}
    s=thrift(9090+i)
    init_queue_reg(s, SIZE/BIN, QUEUE_S)
    iplist=load_file("ips.txt", 18)

    digest_entry = sw.BuildDigestEntry(digest_id=DIGEST_ID)
    sw.SendDigestEntry(digest_entry)
    sw.StreamDigestMessages(digest_id=DIGEST_ID)

    pktin=PacketIn(sw)
    dgin=DigestIn(sw)

    available_idx=Queue()
    flow_evict=Queue()
    chan_queue=Queue()
    flow_loc=Queue()
    flow_rep=Queue()
    expire_queue=Queue()

    te=threading.Thread(target=eviction, args=(i, flow_evict, chan_queue, available_idx, BIN, tuple5, poly, iplist))
    te.start()

    ts=threading.Thread(target=storage, args=(i, flow_loc, h_list, cnt_, bcnt_, type_, swid_, f_dist, BIN))
    ts.start()

    tu=threading.Thread(target=update_queue, args=(i, available_idx, QUEUE_S))
    tu.start()

    thread=threading.Thread(target=con_handle, args=(i, chan_queue, sw, context, eh_list, ecnt_, ebcnt_, eswid_, ef_dist))
    thread.start()

    th=threading.Thread(target=report_expire, args=(i, flow_rep, chan_queue, tuple5, iplist, BIN, poly))
    th.start()

    t=threading.Thread(target=garbage_collector, args=(i, expire_queue, flow_rep, flow_loc))
    t.start()

    tt=threading.Thread(target=PktIn, args=(i, pktin, chan_queue, flow_evict, expire_queue, tuple5))
    tt.start()

    while True:
        digest_list=dgin.sniff(timeout=1)
        for msg in digest_list:
            id_report, proto, src, dst, sport, dport, hval, evic, mf, hval_, cnt, bcnt, pull_idx, h_idx, n_idx=extract_digest(msg.digest)
            if(id_report==1):
                if(mf==1):
                    expire_queue.put([0, hval, time.time(), h_idx, n_idx, 1])
            if(evic==1 and mf==0):
                # To do for FI data collection
                pass
            elif(evic==1 and mf==1):
                flow_evict.put([1, hval_, cnt, bcnt, pull_idx])
                expire_queue.put([1, hval_])

def load_file(fname, num):
    with open(fname, "r") as f:
        poly=[]
        for i in range(num):
            l=f.readline()
            poly.append(l.strip())
    f.close()

    return poly

def save_info(h, cnt_, bcnt_, type_, swid, num, sw_num, dist, pren):

    fname=["tst", "evic", "exp"]
    hash_res=[]
    cnt=[]
    bcnt=[]
    dist_=[]
    for i in range(num):
        hash_res.append([])
        cnt.append([])
        dist_.append([])
        for j in range(sw_num):
            hash_res[i].append([])
            cnt[i].append([])
            dist_[i].append([])

    i=0
    j=0
    for _ in range(len(type_)):
        j=0
        l=len(type_[i])
        for _ in range(l):
            item=type_[i][j]
            idx=j
            if(item==3):
                j+=1
                continue
            hash_res[item][i].append(h[i][idx])
            cnt[item][i].append(cnt_[i][idx])
            dist_[item][i].append(dist[i][idx])
            h[i].pop(idx)
            cnt_[i].pop(idx)
            type_[i].pop(idx)
            swid[i].pop(idx)
            dist[i].pop(idx)
        i+=1

    for ij in range(num):
        fh="flowh_"+fname[ij]+".txt"
        fcnt="flowc_"+fname[ij]+".txt"
        fdist="flowd_" +fname[ij]+".txt"
        with open(pren+fh, "w") as f:
            for i in range(sw_num):
                f.write("%d:\n" % i)
                tmp=[str(j) for j in hash_res[ij][i]]
                f.write(' '.join(tmp))
                f.write("\n\n")
        f.close()
        with open(pren+fcnt, "w") as f:
            for i in range(sw_num):
                f.write("%d:\n" % i)
                tmp=[str(j) for j in cnt[ij][i]]
                f.write(' '.join(tmp))
                f.write("\n\n")
        f.close()
        with open(pren+fdist, "w") as f:
            for i in range(sw_num):
                f.write("%d:\n" % i)
                for k in range(len(dist_[ij][i])):
                    tmp=[str(j) for j in dist_[ij][i][k]]
                    f.write(' '.join(tmp))
                    f.write("\n")
        f.close()

def remove_dup(hash_res, cnt, bcnt, type_, swid, dist):
    for i, v in enumerate(hash_res):
        seen=set()
        uniq_h=[]
        u_cnt=[]
        u_bcnt=[]
        u_type=[]
        u_swid=[]
        u_dist=[]
        for idx, item in enumerate(v):
            if item in seen:
                x=uniq_h.index(item)
                u_cnt[x]=u_cnt[x]+cnt[i][idx]
                u_dist[x]=[a_ + b_ for a_,b_ in zip(u_dist[x], dist[i][idx])]
                continue
            if item not in seen:
                seen.add(item)
                uniq_h.append(item)
                u_cnt.append(cnt[i][idx])
                u_dist.append(dist[i][idx])
                if(len(type_)!=0):
                    u_type.append(type_[i][idx])
                u_swid.append(swid[i][idx])

        if len(hash_res[i])!=len(uniq_h):
            print(len(hash_res[i]), len(uniq_h))
        hash_res[i]=uniq_h
        cnt[i]=u_cnt
        dist[i]=u_dist
        if(len(type_)!=0):
            type_[i]=u_type
        swid[i]=u_swid


def main(p4info_file_path, bmv2_file_path, sw_num):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    polynomial=load_file("polynomial.txt", sw_num)

    #Demo data structure for data collection in control plane 
    sw=[]
    cn=[]
    hash_res_=[]
    cnt_=[]
    bcnt_=[]
    type__=[]
    swid_=[]
    threads=[]
    uniq_tuple=[]
    f_dist=[]
    ef_dist=[]

    h_e_=[]
    cnt_e_=[]
    bcnt_e_=[]
    swid_e_=[]
    port=50051
    try:
        for i in range(sw_num):
            s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s1',
                address='127.0.0.1:%d' % port ,
                device_id=i)#,
                #proto_dump_file='logs/s%d-p4runtime-requests.txt' % i)
            port+=1
            sw.append(s1)
            cn.append(Context())

        for idx,s in enumerate(sw):
            s.MasterArbitrationUpdate()
            s.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                           bmv2_json_file_path=bmv2_file_path)
            cn[idx].set_p4info(s.get_p4info())

        for i in range(sw_num):
            hash_res_.append([])
            cnt_.append([])
            bcnt_.append([])
            type__.append([])
            swid_.append([])
            uniq_tuple.append([])
            f_dist.append([])

            h_e_.append([])
            cnt_e_.append([])
            bcnt_e_.append([])
            swid_e_.append([])
            ef_dist.append([])
            t=threading.Thread(target=controller, args=(i, p4info_helper, sw[i], cn[i], hash_res_[i], cnt_[i], bcnt_[i], type__[i], swid_[i], polynomial, uniq_tuple[i], h_e_[i], cnt_e_[i], bcnt_e_[i], swid_e_[i], ef_dist[i], f_dist[i]))
            threads.append(t)

        for t in threads:
            t.start()
            #for t in threads:
            #t.join()
        while True:
            in_=input("Command:").split()

            if(len(in_)==0):
                continue
            if(in_[0]=="Exit"):
                for t in threads:
                    t.join()
            if(in_[0]=="Clc"):
                resume_event.set()
                pause_event.clear()
                resume_event.clear()
                print("Resumed")
            if(in_[0]=="Snap"):
                fname_="./result/"   
                if not os.path.exists(fname_):
                    os.makedirs(fname_)
                    fname__="./result/Report/"   
                    if not os.path.exists(fname__):
                        os.makedirs(fname__)
                    print(f"Directory '{fname_}' created.")

                pause_event.set()
                time.sleep(10)

                hash_res=copy.deepcopy(hash_res_)
                cnt=copy.deepcopy(cnt_)
                bcnt=copy.deepcopy(bcnt_)
                type_=copy.deepcopy(type__)
                swid=copy.deepcopy(swid_)
                dist=copy.deepcopy(f_dist)
                
                h_e=copy.deepcopy(h_e_)
                cnt_e=copy.deepcopy(cnt_e_)
                bcnt_e=copy.deepcopy(bcnt_e_)
                swid_e=copy.deepcopy(swid_e_)
                dist_e=copy.deepcopy(ef_dist)

                try:
                    remove_dup(hash_res, cnt, bcnt, type_, swid, dist)
                    print("Before: %d " %len(hash_res[1]))
                    save_info(hash_res, cnt, bcnt, type_, swid, 3, sw_num, dist, fname_) 
                    print("After: %d " %len(hash_res[1]))

                    remove_dup(h_e, cnt_e, bcnt_e, [], swid_e, dist_e)
                    h_exp=[]
                    cnt_exp=[]
                    bcnt_exp=[]
                    dist_exp=[]
                    for i in range(sw_num):
                        h_exp.append([])
                        cnt_exp.append([])
                        dist_exp.append([])
                        for j in range(sw_num):
                            h_exp[i].append([])
                            cnt_exp[i].append([])
                            dist_exp[i].append([])

                    for i, v in enumerate(h_e):
                        for idx, item in enumerate(v):
                                index=swid_e[i][idx]
                                h_exp[i][index].append(h_e[i][idx])
                                cnt_exp[i][index].append(cnt_e[i][idx])
                                dist_exp[i][index].append(dist_e[i][idx])

                    for ij in range(sw_num): 
                        with open(fname_+"Report/h_"+str(ij)+".txt", "w") as f:
                            for i in range(sw_num):
                                f.write("%d:\n" % i)
                                tmp=[str(j) for j in h_exp[ij][i]]
                                f.write(' '.join(tmp))
                                f.write("\n\n")
                        f.close()
                        with open(fname_+"Report/c_"+str(ij)+".txt", "w") as f:
                            for i in range(sw_num):
                                f.write("%d:\n" % i)
                                tmp=[str(j) for j in cnt_exp[ij][i]]
                                f.write(' '.join(tmp))
                                f.write("\n\n")
                        f.close()
                        with open(fname_+"Report/d_"+str(ij)+".txt", "w") as f:
                            for i in range(sw_num):
                                f.write("%d:\n" % i)
                                for k in range(len(dist_exp[ij][i])):
                                    tmp=[str(j) for j in dist_exp[ij][i][k]]
                                    f.write(' '.join(tmp))
                                    f.write("\n")
                        f.close()

                except:
                        print("Err!")
                        pass

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch.json')
    parser.add_argument('-n', '--sw_number', help='number of switches', \
                        type=int, required=True, default=9)
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.sw_number)
