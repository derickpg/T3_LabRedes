import select, socket, sys, queue
import struct

ETH_P_ALL = 0x0003

ip_externo = "200.200.200.200"

tabela = []
# [0]PROTOCOLO [1]IP_INTERNO [2]PORTA_INTERNA [3]IP_EXTERNO [4]PORTA_EXTERNA [5]IP_DESTINO [6]PORTA_DESTINO

# TABELA PROTOCOLOS
# ETH_PROTOCOLO = 0x0800 IP (2048) | 0x0806 ARP (2054)
# IP_PROTOCOLO = 0x1 ICMP (1) | 0x6 TCP (6) | 0x11 UDP (17)


def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

# Create 2 sockets, one for each interface eth0 and eth1
try:
    s0 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    s0.bind(('eth0',0))
    s1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    s1.bind(('eth1',0))
except OSError as msg:
    print('Error'+str(msg))
    sys.exit(1)

print('Sockets created!')

inputs = [s0, s1]
outputs = []
message_queues = {}

while inputs:
    readable, writable, exceptional = select.select(
        inputs, outputs, inputs)
    for s in readable:
        (packet,addr) = s.recvfrom(65536)

        eth_length = 14
        ip_length = 20
        tcp_length = 20
        udp_length = 8
        
        eth_header = packet[:eth_length]

        eth = struct.unpack("!6s6sH",eth_header)
        eth_protocol = eth[2];
        
        interface = "eth0" if s is s0 else "eth1"
        print("Received from "+interface)
        # print("MAC Dst: "+bytes_to_mac(eth[0]))
        # print("MAC Src: "+bytes_to_mac(eth[1]))
        # print("Type: "+hex(eth[2]) + " ~ {0}".format(eth[2]))
        # #print("IP Src: "+s_addr + " // IP Dst: "+d_addr)

        if s is s0 : # eth0 - 00:00:00:aa:00:01
            if eth_protocol == 2048 : # IP

                ip_header = packet[eth_length:ip_length+eth_length]
                ipx = struct.unpack("!BBHHHBBH4s4s", ip_header)
                ip_protocol = ipx[6]
                ip_interno = socket.inet_ntoa(ipx[8])
                ip_destino = socket.inet_ntoa(ipx[9])
                #ipheader = 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
                #          |V|T|LEN|IDE|OFF|T|P|CHECK|IP_DESTINO |IP_ORIGEM |
                new_ip_header = ip_header[:12] + socket.inet_aton(ip_externo) + ip_header[16:]

                if ip_protocol == 1 : # ICMP
                    tabela.append(["ICMP", ip_interno, "", ip_externo, "", ip_destino, ""])
                    packet = eth_header + new_ip_header + packet[eth_length+ip_length:]
                    s1.send(packet)

                if ip_protocol == 6 : # TCP
                    tcp_header = packet[eth_length+ip_length:tcp_length+eth_length+ip_length]
                    new_tcp_header = tcp_header
                    tcpx = struct.unpack("!HHLLBBHHH", tcp_header)
                    porta_origem = tcpx[1]
                    porta_destino = tcpx[2]
                    muda_porta = False
                    for linha in tabela :
                        if(linha[3] == ip_externo and linha[4] == porta_origem and linha[5] == ip_destino and linha[6] == porta_destino) :
                            muda_porta = True
                            break
                    if(muda_porta):
                        new_tcp_header = (porta_origem+1) + tcp_header[4:]
                        porta_origem = porta_origem + 1

                    tabela.append(["TCP", ip_interno, porta_origem, ip_externo, porta_origem, ip_destino, porta_destino])
                    packet = eth_header + new_ip_header + new_tcp_header + packet[eth_length+ip_length+tcp_length:]
                    s1.send(packet)

                if ip_protocol == 17 : # UDP
                    udp_header = packet[eth_length+ip_length:udp_length+eth_length+ip_length]
                    new_udp_header = udp_header
                    udpx = struct.unpack("!HHHH", udp_header)
                    porta_origem = udpx[1]
                    porta_destino = udpx[2]
                    muda_porta = False
                    for linha in tabela :
                        if(linha[3] == ip_externo and linha[4] == porta_origem and linha[5] == ip_destino and linha[6] == porta_destino) :
                            muda_porta = True
                            break
                    if(muda_porta):
                        new_udp_header = (porta_origem+1) + tcp_header[4:]
                        porta_origem = porta_origem + 1

                    tabela.append(["UDP", ip_interno, porta_origem, ip_externo, porta_origem, ip_destino, porta_destino])
                    packet = eth_header + new_ip_header + new_udp_header + packet[eth_length+ip_length+udp_length:]
                    s1.send(packet)

        else :
            # COISAS VINDO DE FORA DA REDE INTERNA
            # [0]PROTOCOLO [1]IP_INTERNO [2]PORTA_INTERNA [3]IP_EXTERNO [4]PORTA_EXTERNA [5]IP_DESTINO [6]PORTA_DESTINO
            if eth_protocol == 2048 : # IP

                ip_header = packet[eth_length:ip_length+eth_length]
                ipx = struct.unpack("!BBHHHBBH4s4s", ip_header)
                ip_protocol = ipx[6]
                ip_destinatario = socket.inet_ntoa(ipx[8])
                ip_destino = socket.inet_ntoa(ipx[9])

                if ip_protocol == 1 : # ICMP

                    for linha in tabela :
                        if(linha[0] == "ICMP" and linha[3] == ip_destinatario and linha[4] == "" and linha[5] == ip_destino and linha[6] == "") :
                            ip_interno = linha[1]
                            tabela.remove(linha)
                            break

                    #ipheader = 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
                    #          |V|T|LEN|IDE|OFF|T|P|CHECK|IP_DESTINO |IP_ORIGEM |
                    new_ip_header = ip_header[:12] + socket.inet_aton(ip_interno) + ip_header[16:]

                    packet = eth_header + new_ip_header + packet[eth_length+ip_length:]
                    s0.send(packet)

                if ip_protocol == 6 : # TCP
                    tcp_header = packet[eth_length+ip_length:tcp_length+eth_length+ip_length]
                    tcpx = struct.unpack("!HHLLBBHHH", tcp_header)
                    porta_origem = tcpx[1]
                    porta_destino = tcpx[2]

                    for linha in tabela :
                        if(linha[0] == "TCP" and linha[3] == ip_destinatario and linha[4] == porta_origem and linha[5] == ip_destino and linha[6] == porta_destino) :
                            ip_interno = linha[1]
                            porta_origem = linha[2]
                            tabela.remove(linha)
                            break

                    #ipheader = 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
                    #          |V|T|LEN|IDE|OFF|T|P|CHECK|IP_DESTINO |IP_ORIGEM |
                    new_ip_header = ip_header[:12] + socket.inet_aton(ip_interno) + ip_header[16:]

                    #new_tcp_header = +tcp_header ---- porta interna muda????
                    packet = eth_header + new_ip_header + tcp_header + packet[eth_length+ip_length+tcp_length:]
                    s0.send(packet)

                if ip_protocol == 17 : # UDP
                    udp_header = packet[eth_length+ip_length:udp_length+eth_length+ip_length]
                    udpx = struct.unpack("!HHHH", udp_header)
                    porta_origem = udpx[1]
                    porta_destino = udpx[2]

                    for linha in tabela :
                        if(linha[0] == "UDP" and linha[3] == ip_destinatario and linha[4] == porta_origem and linha[5] == ip_destino and linha[6] == porta_destino) :
                            ip_interno = linha[1]
                            porta_origem = linha[2]
                            tabela.remove(linha)
                            break

                    #ipheader = 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
                    #          |V|T|LEN|IDE|OFF|T|P|CHECK|IP_DESTINO |IP_ORIGEM |
                    new_ip_header = ip_header[:12] + socket.inet_aton(ip_interno) + ip_header[16:]

                    #new_udp_header =  ---- porta interna muda????
                    packet = eth_header + new_ip_header + udp_header + packet[eth_length+ip_length+udp_length:]
                    s0.send(packet)

