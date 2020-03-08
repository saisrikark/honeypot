import pyshark
import threading 
import time

capture = pyshark.LiveCapture(interface = 'wlp19s0')
j = 0

def write_into_file(capture_list,start_index,end_index):
    for i in range(start_index,end_index):
        try:
            global j 
            packet_log = str(j) + " " + str(capture_list[i].sniff_timestamp) + " "
            j = j + 1
            try:
                packet_log = packet_log + capture_list[i]['eth'].src + " " + capture_list[i]['eth'].dst + " "
            except:
                packet_log = packet_log + "NA" + " " + "NA" + " "
            try:
                packet_log = packet_log + capture_list[i][capture_list[i].transport_layer.lower()].srcport + " " + capture_list[i][capture_list[i].transport_layer.lower()].dstport + " "
            except:
                packet_log = packet_log + "NA" + " " + "NA" + " "
            if("ip" in capture_list[i]):
                packet_log = packet_log + capture_list[i]['ip'].src + " " + capture_list[i]['ip'].dst + "\n"
            else:
                packet_log = packet_log + capture_list[i]['ipv6'].src + " " + capture_list[i]['ipv6'].dst + "\n"
            fp = open("packets.log", "a")
            fp.write(packet_log)
            fp.close()
        except:
            fp = open("packets.log","a")
            fp.write("Failed To Log The Packet\n")
            fp.close()

def read_packets():
    while(len(capture) == 0):
        time.sleep(5)
    older_count = 0
    while(True):
        new_count = len(capture)
        if(new_count != older_count):
            print("Writing packets from " + str(older_count + 1) + " to " + str(new_count))
            write_into_file(capture,older_count,new_count)
            older_count = new_count
            time.sleep(10)

t1 = threading.Thread(target=read_packets)
t1.start()
capture.sniff()


