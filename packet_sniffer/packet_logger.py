import pyshark

capture = pyshark.LiveCapture(interface = 'wlp19s0')
capture.sniff(timeout = 10)
no_of_packets = len(capture)
j = 0
for i in capture:
    try:
        fp = open("packets.log", "a")
        packet_log = str(j) + " " + str(i.sniff_timestamp) + " "
        j = j + 1
        packet_log = packet_log + i['eth'].src + " " + i['eth'].dst + " " 
        packet_log = packet_log + i[i.transport_layer.lower()].srcport + " " + i[i.transport_layer.lower()].dstport + " "
        if("ip" in i):
            packet_log = packet_log + i['ip'].src + " " + i['ip'].dst + "\n"
        else:
            packet_log = packet_log + i['ipv6'].src + " " + i['ipv6'].dst + "\n"
        fp.write(packet_log)
        fp.close()
    except:
        pass

        


    



