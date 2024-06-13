#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
from time import sleep

def reset_registers(thrift_port=9090):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        i="counter_reset MyIngress.tf" + "\n"
        i= i + "register_reset MyIngress.hash_check_register" + "\n"
        i= i + "register_reset MyIngress.packet_cnt" + "\n"
        i= i + "register_reset MyIngress.packet_bcnt" + "\n"
        stdout, stderr = p.communicate(input=i.encode())
        stdout=stdout.decode()
        print(stdout)


def change_polynomial(poly, thrift_port=9090):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        i="set_crc32_parameters calc %s 0 0 True True" % (poly) + "\n"
        i= i + "set_crc32_parameters calc_0 %s 0 0 True True" % (poly) + "\n"
        i= i + "set_crc32_parameters calc_1 %s 0 0 True True" % (poly) + "\n"
        i= i + "set_crc32_parameters calc_2 %s 0 0 True True" % (poly) + "\n"
        i= i + "set_crc32_parameters calc_3 %s 0 0 True True" % (poly) + "\n"
        print(i)
        stdout, stderr = p.communicate(input=i.encode())
        stdout=stdout.decode()
        print(stdout)

def mirror_config(thrift_port=9090):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        i="mirroring_add 200 64 " + "\n"
        print(i)
        stdout, stderr = p.communicate(input=i.encode())
        stdout=stdout.decode()
        print(stdout)

def write_rules(rules, thrift_port=9090):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        i="".join(rules)
        #print(i)
        stdout, stderr = p.communicate(input=i.encode())
        stdout=stdout.decode()
        print(stdout)

def write_swid(table, i, thrift_port=9090):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        i="register_write %s 0 %d" % (table, i)
        #print(i)
        stdout, stderr = p.communicate(input=i.encode())
        stdout=stdout.decode()
        print(stdout)

def read_register(register, thrift_port=9090, idx=-1):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if idx==-1:
            i="register_read %s" % (register)
            flg=0
        else:
            i="register_read %s %d" % (register, idx)
            flg=1
        stdout, stderr = p.communicate(input=i.encode())
        stdout=stdout.decode()
        if flg==1:
            reg_val = [l for l in stdout.split('\n') if ' %s[%d]' % (register, idx) in l][0].split('= ', 1)[1]
            l=reg_val
        else:
            reg_val = [l for l in stdout.split('\n') if '=' in l][0].split('= ', 1)[1]
            l=reg_val.split(',')
        return l
def read_counter(counter, thrift_port=9090, idx="0", print_=False):
        p = subprocess.Popen(['simple_switch_CLI', '--thrift-port', str(thrift_port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        i="counter_read %s %s" % (counter, idx)
        stdout, stderr = p.communicate(input=i.encode())
        stdout=stdout.decode()
        cnt_val = [l for l in stdout.split('\n') if '=' in l][0].split('= ', 1)[1]
        if (print_):
            print(cnt_val)
        return cnt_val

def write_rules_f(fname, sw_num):
    with open(fname, "r") as f:
        rules=[]
        si=-1
        port=0
        while True:
            l=f.readline()
            if (("#" in l) and len(rules)!=0) or not l :
                write_rules(rules, str(port))
                rules.clear()
                if (si + 1 == sw_num):
                    break
            if("#" in l):
                si=si+1
                port=9090+si
                continue
            if( not l ):
                break
            rules.append(l)
    f.close()

def main(sw_num, write, read, poly, flush):
        
        if (read):
            with open('registers', 'w') as f:
                for si in range(sw_num):
                    port=str(9090+si)
                    l1=read_register("MyIngress.hash_check_register", port)
                    f.write("\n\n%d:\n"% (si))
                    f.write(' '.join(l1))
            f.close()
            with open('counter', 'w') as f:
                for si in range(sw_num):
                    port=str(9090+si)
                    l1=read_register("MyIngress.packet_cnt", port)
                    f.write("\n\n%d:\n"% (si))
                    f.write(' '.join(l1))
            f.close()
            with open('path_reg', 'w') as f:
                for si in range(sw_num):
                    port=str(9090+si)
                    l1=read_register("MyIngress.path_reg", port)
                    f.write("\n\n%d:\n"% (si))
                    f.write(' '.join(l1))
            f.close()
            with open('Hflow_of', 'w') as f:
                for si in range(sw_num):
                    port=str(9090+si)
                    l1=read_register("MyIngress.Hflow_off", port)
                    f.write("\n\n%d:\n"% (si))
                    f.write(' '.join(l1))
            f.close()
            with open('reg_grid', 'w') as f:
                for si in range(sw_num):
                    port=str(9090+si)
                    l1=read_register("MyIngress.reg_grid", port)
                    f.write("\n%d:\n"% (si))
                    for k in range(0, len(l1), 94):
                        f.write(' '.join(list(l1[k:k+94])))
                        f.write('\n')
            f.close()
        if (write):
            with open("path.json", "r") as f:
                rules=[]
                si=-1
                port=0
                while True:
                    l=f.readline()
                    if (("#" in l) and len(rules)!=0) or not l :
                        write_rules(rules, str(port))
                        rules.clear()
                        if (si + 1 == sw_num):
                            break
                    if("#" in l):
                        si=si+1
                        port=9090+si
                        continue
                    if( not l ):
                        break
                    rules.append(l)
            f.close()
        if (poly):
            sleep(2)
            with open("polynomial.txt", "r") as f:
                port=0
                for i in range(sw_num):
                    port = 9090 + i 
                    l=f.readline()
                    change_polynomial(l.strip(), port)
            f.close()
        if (flush):
            port=0
            for i in range(sw_num):
                port = 9090 + i 
                reset_registers(str(port))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Thrift Controller')
    parser.add_argument('-n', '--sw_number', help='number of switches', \
                        type=int, required=True, default=9)
    parser.add_argument('-w', '--wrules', help='write rules from route.txt', \
                        action="store_true", required=False, default=False)
    parser.add_argument('-r', '--rdata', help='read counter and register data', \
                        action="store_true", required=False, default=False)
    parser.add_argument('-c', '--crc-polynomial-change', help='change crc32 polynomial', \
                        action="store_true", required=False, default=False)
    parser.add_argument('-f', '--flush_registers', help='reset all registers', \
                        action="store_true", required=False, default=False)
    args = parser.parse_args()

    main(args.sw_number, args.wrules, args.rdata, args.crc_polynomial_change, args.flush_registers)
