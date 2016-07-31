import string
import struct


class IPv4Address(object):
    """
    >>> ip1 = IPv4Address('192.168.0.1')
    >>> ip2 = IPv4Address('\x7f\x00\x00\x01')
    >>> ip1.in_bytes
    '\xc0\xa8\x00\x01'
    >>> ip2.in_string
    '127.0.0.1'
    >>> ip2.in_string = '8.8.8.8'
    >>> ip2.in_bytes
    '\x08\x08\x08\x08'
    """
    LENGTH = 4

    def __init__(self, address):
        assert isinstance(address, str)
        if len(address) == IPv4Address.LENGTH:
            # when address is in raw bytes form
            self.in_bytes = address
        else:
            # when address is in dot-decimal notation.
            self.in_string = address

    @property
    def in_string(self):
        return '.'.join('{:d}'.format(ord(byte)) for byte in self.in_bytes)

    @in_string.setter
    def in_string(self, address):
        try:
            in_integers = map(int, address.split('.'))
            assert len(in_integers) == 4
        except (AssertionError, ValueError, TypeError):
            raise ValueError('address is not in right form.')
        self.in_bytes = struct.pack('<BBBB', *in_integers)

    def __repr__(self):
        return 'IPv4Address({})'.format(self.in_string)

    def __eq__(self, other):
        assert isinstance(other, IPv4Address)
        return self.in_bytes == other.in_bytes

    def __ne__(self, other):
        assert isinstance(other, IPv4Address)
        return self.in_bytes != other.in_bytes


class MacAddress(object):
    LENGTH = 6

    def __init__(self, address):
        assert isinstance(address, str)
        if len(address) == MacAddress.LENGTH:
            # when address is in raw bytes form
            self.in_bytes = address
        else:
            # when address is in form with 12 hex digits.
            # for example 'xx:xx:xx:xx:xx:xx' or 'xx-xx-xx-xx-xx-xx'
            #  or 'xxxxxx-xxxxxx' or 'xxxxxxxxxxxx'
            hexonly = ''.join(c for c in address if c in string.hexdigits)
            if len(hexonly) != 12:
                raise ValueError('MAC address is not in right form. ({} hex digits not 12)'.format(len(hexonly)))
            self.in_bytes = hexonly.decode('hex')

    @property
    def in_string(self):
        return ':'.join('{:02X}'.format(byte) for byte in self.in_bytes)

    def __repr__(self):
        return 'MacAddress({})'.format(self.in_string)


class Ethernet(object):
    TYPE_ARP = 0x0806
    BROADCAST = MacAddress('ff:ff:ff:ff:ff:ff')

    def __init__(self, raw_packet=None):
        if raw_packet is None:
            self.destination_mac = None
            self.source_mac = None
            self.type = None
            self.data = None
        else:
            self.destination_mac = MacAddress(raw_packet[:6])
            self.source_mac = MacAddress(raw_packet[6:12])
            self.type = struct.unpack('!H', raw_packet[12:14])
            self.data = raw_packet[14:]

    def header_as_bytes(self):
        return ''.join((
            self.destination_mac.in_bytes,
            self.source_mac.in_bytes,
            struct.pack('!H', self.type)
        ))


class ARP(object):
    HARDWARE_ETHERNET = 1
    PROTO_IPv4 = 0x0800
    OP_REQUEST = 1
    OP_REPLY = 2

    def __init__(self, raw_packet=None):
        if raw_packet is None:
            self.ethernet = Ethernet()
            self.hardware_type = None
            self.protocol_type = None
            self.hardware_size = None
            self.protocol_size = None
            self.operation = None
            self.sender_hardware_address = None
            self.sender_protocol_address = None
            self.target_hardware_address = None
            self.target_protocol_address = None
        else:
            self.ethernet = Ethernet(raw_packet)
            raw_arp = self.ethernet.data

            self.hardware_type = struct.unpack('!H', raw_arp[:2])[0]
            self.protocol_type = struct.unpack('!H', raw_arp[2:4])[0]
            self.hardware_size = struct.unpack('!B', raw_arp[4])[0]
            self.protocol_size = struct.unpack('!B', raw_arp[5])[0]
            self.operation = struct.unpack('!H', raw_arp[6:8])[0]
            self.sender_hardware_address = MacAddress(raw_arp[8:14])
            self.sender_protocol_address = IPv4Address(raw_arp[14:18])
            self.target_hardware_address = MacAddress(raw_arp[18:24])
            self.target_protocol_address = IPv4Address(raw_arp[24:28])

    def as_bytes(self):
        return ''.join((
            self.ethernet.header_as_bytes(),
            struct.pack('!H', self.hardware_type),
            struct.pack('!H', self.protocol_type),
            struct.pack('!B', self.hardware_size),
            struct.pack('!B', self.protocol_size),
            struct.pack('!H', self.operation),
            self.sender_hardware_address.in_bytes,
            self.sender_protocol_address.in_bytes,
            self.target_hardware_address.in_bytes,
            self.target_protocol_address.in_bytes
        ))

    def __str__(self):
        return self.as_bytes()


# some usual ARP presets
def normal_request_arp(asker_mac, asker_ip, target_ip):
    arp = ARP()
    arp.ethernet.destination_mac = Ethernet.BROADCAST
    arp.ethernet.source_mac = asker_mac
    arp.ethernet.type = Ethernet.TYPE_ARP

    arp.hardware_type = ARP.HARDWARE_ETHERNET
    arp.protocol_type = ARP.PROTO_IPv4
    arp.hardware_size = MacAddress.LENGTH
    arp.protocol_size = IPv4Address.LENGTH

    arp.operation = ARP.OP_REQUEST
    arp.sender_hardware_address = asker_mac
    arp.sender_protocol_address = asker_ip
    arp.target_hardware_address = MacAddress('00:00:00:00:00:00')
    arp.target_protocol_address = target_ip
    return arp


def normal_reply_arp(replier_mac, replier_ip, recipient_mac, recipient_ip):
    arp = ARP()
    arp.ethernet.destination_mac = recipient_mac
    arp.ethernet.source_mac = replier_mac
    arp.ethernet.type = Ethernet.TYPE_ARP

    arp.hardware_type = ARP.HARDWARE_ETHERNET
    arp.protocol_type = ARP.PROTO_IPv4
    arp.hardware_size = MacAddress.LENGTH
    arp.protocol_size = IPv4Address.LENGTH

    arp.operation = ARP.OP_REPLY
    arp.sender_hardware_address = replier_mac
    arp.sender_protocol_address = replier_ip
    arp.target_hardware_address = recipient_mac
    arp.target_protocol_address = recipient_ip
    return arp


class IP(object):
    def __init__(self, raw_packet=None):
        if raw_packet is None:
            self.ethernet = Ethernet()
            self.version = None
            self.type_of_service = None
            self.header_length_in_words = None
            self.total_length = None
            self.fragment_identifier = None
            self.fragmentation_flag = None
            self.fragmentation_offset = None
            self.time_to_live = None
            self.protocol = None
            self.header_checksum = None
            self.source_address = None
            self.destination_address = None
            self.data = None
        else:
            self.ethernet = Ethernet(raw_packet)
            raw_ip = self.ethernet.data

            first_byte = struct.unpack('!B', raw_ip[0])[0]
            self.version = first_byte & 0xf
            self.header_length_in_words = first_byte >> 4
            self.type_of_service = struct.unpack('!B', raw_ip[1])[0]
            self.total_length = struct.unpack('!H', raw_ip[2:4])[0]
            self.fragment_identifier = struct.unpack('!H', raw_ip[4:6])
            self.fragment_flag = struct.unpack('!H', raw_ip[6])[0] & 0b111
            self.fragment_offset = struct.unpack('!H', raw_ip[6:8])[0] >> 3
            self.time_to_live = struct.unpack('!B', raw_ip[8])[0]
            self.protocol = struct.unpack('!B', raw_ip[9])[0]
            self.header_checksum = struct.unpack('!H', raw_ip[10:12])[0]
            self.source_address = IPv4Address(raw_ip[12:16])
            self.destination_address = IPv4Address(raw_ip[16:20])
            self.data = raw_ip[20:]
