import pyshark
import threading 
import time
import signal
import sys


###############################Global Variables and Locks##################
interface_name = "wlan0"
capture = pyshark.LiveCapture(interface = interface_name)
turn_off_flag = False
writing_into_file_flag = False
clearing_list_flag = False
packet_beginning_index = 0
packet_ending_index = 0
logging_interval = 5
clear_list_interval = 100
clear_list_packet_threshold = 100
##########################################################################


############################################################################
def signal_handler(sif, frame):
    print("\n")
    print("Command Received To Terminate The Program") 
    global turn_off_flag
    turn_off_flag = True
    sys.exit()
############################################################################


##############################Logging component##############################
def write_into_file(capture_list,start_index,end_index):
    packet_logs_text = str()
    print("Writing", end_index-start_index, "packets into file")
    for i in range(start_index,end_index):
        try:
            packet_log = str(capture_list[i].sniff_timestamp) + " "
            try:
                packet_log += capture_list[i]['eth'].src + " " + capture_list[i]['eth'].dst + " "
            except:
                packet_log += "NA" + " " + "NA" + " "
            try:
                packet_log += capture_list[i][capture_list[i].transport_layer.lower()].srcport + " " + capture_list[i][capture_list[i].transport_layer.lower()].dstport + " "
            except:
                packet_log += "NA" + " " + "NA" + " "
            if("ip" in capture_list[i]):
                packet_log += capture_list[i]['ip'].src + " " + capture_list[i]['ip'].dst + "\n"
            else:
                packet_log += capture_list[i]['ipv6'].src + " " + capture_list[i]['ipv6'].dst + "\n"
            packet_logs_text += packet_log
        except:
            pass
    fp = open("packets.log", "a")
    fp.write(packet_logs_text)
    fp.close()

def logger():
    global packet_beginning_index
    global packet_ending_index
    global writing_into_file_flag
    while(True):
        time.sleep(logging_interval)
        while(clearing_list_flag):
            pass
        packet_ending_index = len(capture)
        if(packet_ending_index - packet_beginning_index):
            writing_into_file_flag = True
            write_into_file(capture, packet_beginning_index, packet_ending_index)
            writing_into_file_flag = False
        else:
            print("No packets detected in ", logging_interval, "seconds")
        packet_beginning_index = packet_ending_index
        if(turn_off_flag):
            break
#############################################################################

def sniff_packets():
    capture.sniff()

def clear_list_helper():
    global clearing_list_flag
    global packet_beginning_index
    global packet_ending_index
    while(writing_into_file_flag):
        pass
    clearing_list_flag = True
    capture.clear()
    packet_beginning_index = 0
    packet_ending_index = 0
    clearing_list_flag = False
    print("Clearing list")

def clear_list():
    while(True):
        if(len(capture) > clear_list_packet_threshold):
            clear_list_helper()
        time.sleep(clear_list_interval)
        if(turn_off_flag):
            break

sniff_packets_thread = threading.Thread(target=sniff_packets)
log_packets_thread = threading.Thread(target=logger)
clear_list_thread = threading.Thread(target=clear_list)

sniff_packets_thread.start()
log_packets_thread.start()
clear_list_thread.start()

signal.signal(signal.SIGINT, signal_handler)
