#!/usr/bin/python
# 
#eBPF application that filters SIP packets
#and extracts (and prints on screen) the first line of the SIP message.
#
#eBPF program sip_filter is used as SOCKET_FILTER attached to lo interface.
#only packet of type ip and tcp containing SIP messages at a fixed port number are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the SIP message

from __future__ import print_function
from bcc import BPF
from sys import argv
from time import sleep

import sys
import socket
import os

#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("")
    print("examples:")
    print("    sip-filter              # bind socket to eth0")
    print("    sip-filter -i wlan0     # bind socket to wlan0")
    exit()

#arguments
interface="eth0"

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i':
    interface = argv[2]
  else:
    usage()

if len(argv) > 3:
  usage()

print ("binding socket to '%s'" % interface)

# initialize BPF - load source code from sip-filter.c
bpf = BPF(src_file = "sip-filter.c",debug = 0)

#load eBPF program sip_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_sip_filter = bpf.load_func("sip_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_sip_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_sip_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

while True:
  sleep(0.2)
  s = ""
  if len(bpf["sip_message"].items()):
      mp={}
      for k,v in bpf["sip_message"].items():
        mp[k.value]=v.value
      print(len(bpf["sip_message"].items()))
      for i in range(len(bpf["sip_message"].items())):
        s += chr(mp[i])
      print(s)
      bpf["sip_message"].clear()
      mp.clear()
