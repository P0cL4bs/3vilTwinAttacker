import IN
import time
import socket
import struct
from collections import defaultdict
from PyQt4.QtCore import QThread,pyqtSignal,QObject


class OutOfLeasesError(Exception):
    pass

# Original from http://code.activestate.com/recipes/491264/ (r4)
class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.dominio = ''
        # Copy Opcode to variable 'tipo'.
        tipo = (ord(data[2]) >> 3) & 15
        if tipo == 0: # Opcode 0 mean a standard query(QUERY)
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.dominio += data[ini + 1:ini + lon + 1] + '.'
                ini += lon + 1
                lon = ord(data[ini])

    def respuesta(self, ip):
        packet = ''
        if self.dominio:
            packet += self.data[:2] + "\x81\x80"                            # Response & No error.
            packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'  # Questions and Answers Counts.
            packet += self.data[12:]                                        # Original Domain Name Question.
            packet += '\xc0\x0c'                                            # A domain name to which this resource record pertains.
            packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'            # type, class, ttl, data-length
            packet += str.join('', map(lambda x: chr(int(x)), ip.split('.')))
        return packet

# Original https://github.com/NORMA-Inc/AtEar/blob/master/module/fake_ap.py
class DNSServer(QThread):
    def __init__(self, iface, address):
        super(DNSServer, self).__init__(parent = None)
        self.iface = iface
        self.DnsLoop = True
        self.address = address

    def run(self):
        self.dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dns_sock.settimeout(0.3)  # Set timeout on socket-operations.
        time.sleep(0.5)
        self.dns_sock.bind(('', 53))
        while self.DnsLoop:
            try:
                data, addr = self.dns_sock.recvfrom(1024)
            except:
                continue
            packet = DNSQuery(data)
            # Return own IP adress.
            self.dns_sock.sendto(packet.respuesta(self.address), addr)
        self.dns_sock.close()

    def stop(self):
        self.DnsLoop = False
        self.dns_sock.close()
        self.terminate()




# https://github.com/NORMA-Inc/AtEar/blob/master/module/fake_ap.py
class DHCPServer(QThread):
    '''
        Original from https://github.com/psychomario/PyPXE

        This class implements a DHCP Server, limited to PXE options.
        Implemented from RFC2131, RFC2132,
        https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol,
        and http://www.pix.net/software/pxeboot/archive/pxespec.pdf.
    '''
    sendConnetedClient = pyqtSignal(object)
    def __init__(self,iface,dhcp_options=dict()):
        super(DHCPServer, self).__init__(parent = None)
        self.dhcp_options = dhcp_options
        self.iface        = iface
        # If SO_BINDTODEVICE is present, it is possible for dhcpd to operate on Linux with more than one network interface.
        # man 7 socket
        if not hasattr(IN, "SO_BINDTODEVICE"):
            IN.SO_BINDTODEVICE = 25
        self.LoopDhcpStatus = True
        self.ip = self.dhcp_options['router']
        self.port = 67
        self.offer_from = self.dhcp_options['range'].split('/')[0]
        self.offer_to = self.dhcp_options['range'].split('/')[1]
        self.subnet_mask = self.dhcp_options['netmask']
        self.router = self.dhcp_options['router']
        self.dns_server = '8.8.8.8' # share internet
        self.broadcast = '<broadcast>'
        self.file_server = self.ip
        self.file_name = '' # ??
        if not self.file_name:
            self.force_file_name = False
            self.file_name = 'pxelinux.0'
        else:
            self.force_file_name = True
        self.ipxe = False
        self.http = False
        self.mode_proxy = False
        self.static_config = dict()
        self.whitelist = False
        self.mode_debug = False
        # The value of the magic-cookie is the 4 octet dotted decimal 99.130.83.99
        #   (or hexadecimal number 63.82.53.63) in network byte order.
        #   (this is the same magic cookie as is defined in RFC 1497 [17])
        # In module struct '!' mean Big-endian
        #   'I' mean unsigned int
        self.magic = struct.pack('!I', 0x63825363) # magic cookie.

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, self.iface + '\0')
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.port))

        # Specific key is MAC
        self.options = dict()
        self.leases = defaultdict(lambda: {'ip': '', 'expire': 0, 'ipxe': self.ipxe})


    def get_namespaced_static(self, path, fallback = {}):
        statics = self.static_config
        for child in path.split('.'):
            statics = statics.get(child, {})
        return statics if statics else fallback

    def next_ip(self):
        '''
            This method returns the next unleased IP from range;
            also does lease expiry by overwrite.
        '''

        # if we use ints, we don't have to deal with octet overflow
        # or nested loops (up to 3 with 10/8); convert both to 32-bit integers

        # e.g '192.168.1.1' to 3232235777
        encode = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]

        # e.g 3232235777 to '192.168.1.1'
        decode = lambda x: socket.inet_ntoa(struct.pack('!I', x))

        from_host = encode(self.offer_from)
        to_host = encode(self.offer_to)

        # pull out already leased IPs
        leased = [self.leases[i]['ip'] for i in self.leases
                if self.leases[i]['expire'] > time.time()]

        # convert to 32-bit int
        leased = map(encode, leased)

        # loop through, make sure not already leased and not in form X.Y.Z.0
        for offset in xrange(to_host - from_host):
            if (from_host + offset) % 256 and from_host + offset not in leased:
                return decode(from_host + offset)
        raise OutOfLeasesError('Ran out of IP addresses to lease!')

    def tlv_encode(self, tag, value):
        '''Encode a TLV option.'''
        return struct.pack('BB', tag, len(value)) + value

    def tlv_parse(self, raw):
        '''Parse a string of TLV-encoded options.'''
        ret = {}
        while(raw):
            [tag] = struct.unpack('B', raw[0])
            if tag == 0: # padding
                raw = raw[1:]
                continue
            if tag == 255: # end marker
                break
            [length] = struct.unpack('B', raw[1])
            value = raw[2:2 + length]
            raw = raw[2 + length:]
            if tag in ret:
                ret[tag].append(value)
            else:
                ret[tag] = [value]
        return ret

    def get_mac(self, mac):
        '''
            This method converts the MAC Address from binary to
            human-readable format for logging.
        '''
        return ':'.join(map(lambda x: hex(x)[2:].zfill(2), struct.unpack('BBBBBB', mac))).upper()

    def craft_header(self, message):
        '''This method crafts the DHCP header using parts of the message.'''
        xid, flags, yiaddr, giaddr, chaddr = struct.unpack('!4x4s2x2s4x4s4x4s16s', message[:44])
        client_mac = chaddr[:6]

        # op, htype, hlen, hops, xid
        response =  struct.pack('!BBBB4s', 2, 1, 6, 0, xid)
        if not self.mode_proxy:
            response += struct.pack('!HHI', 0, 0, 0) # secs, flags, ciaddr
        else:
            response += struct.pack('!HHI', 0, 0x8000, 0)
        if not self.mode_proxy:
            if self.leases[client_mac]['ip']: # OFFER
                offer = self.leases[client_mac]['ip']
            else: # ACK
                offer = self.get_namespaced_static('dhcp.binding.{0}.ipaddr'.format(self.get_mac(client_mac)))
                offer = offer if offer else self.next_ip()
                self.leases[client_mac]['ip'] = offer
                self.leases[client_mac]['expire'] = time.time() + 86400
            response += socket.inet_aton(offer) # yiaddr
        else:
            response += socket.inet_aton('0.0.0.0')
        response += socket.inet_aton(self.file_server) # siaddr
        response += socket.inet_aton('0.0.0.0') # giaddr
        response += chaddr # chaddr

        # BOOTP legacy pad
        response += chr(0) * 64 # server name
        if self.mode_proxy:
            response += self.file_name
            response += chr(0) * (128 - len(self.file_name))
        else:
            response += chr(0) * 128
        response += self.magic # magic section
        return (client_mac, response)

    def craft_options(self, opt53, client_mac):
        '''
            @brief This method crafts the DHCP option fields
            @param opt53:
            *    2 - DHCPOFFER
            *    5 - DHCPACK
            @see RFC2132 9.6 for details.
        '''
        response = self.tlv_encode(53, chr(opt53)) # message type, OFFER
        response += self.tlv_encode(54, socket.inet_aton(self.ip)) # DHCP Server
        if not self.mode_proxy:
            subnet_mask = self.get_namespaced_static('dhcp.binding.{0}.subnet'.format(self.get_mac(client_mac)), self.subnet_mask)
            response += self.tlv_encode(1, socket.inet_aton(subnet_mask)) # subnet mask
            router = self.get_namespaced_static('dhcp.binding.{0}.router'.format(self.get_mac(client_mac)), self.router)
            response += self.tlv_encode(3, socket.inet_aton(router)) # router
            dns_server = self.get_namespaced_static('dhcp.binding.{0}.dns'.format(self.get_mac(client_mac)), [self.dns_server])
            dns_server = ''.join([socket.inet_aton(i) for i in dns_server])
            response += self.tlv_encode(6, dns_server)
            response += self.tlv_encode(51, struct.pack('!I', 86400)) # lease time

        # TFTP Server OR HTTP Server; if iPXE, need both
        response += self.tlv_encode(66, self.file_server)

        # file_name null terminated
        if not self.ipxe or not self.leases[client_mac]['ipxe']:
            # http://www.syslinux.org/wiki/index.php/PXELINUX#UEFI
            if 93 in self.leases[client_mac]['options'] and not self.force_file_name:
                [arch] = struct.unpack("!H", self.leases[client_mac]['options'][93][0])
                if arch == 0: # BIOS/default
                    response += self.tlv_encode(67, 'pxelinux.0' + chr(0))
                elif arch == 6: # EFI IA32
                    response += self.tlv_encode(67, 'syslinux.efi32' + chr(0))
                elif arch == 7: # EFI BC, x86-64 (according to the above link)
                    response += self.tlv_encode(67, 'syslinux.efi64' + chr(0))
                elif arch == 9: # EFI x86-64
                    response += self.tlv_encode(67, 'syslinux.efi64' + chr(0))
            else:
                response += self.tlv_encode(67, self.file_name + chr(0))
        else:
            response += self.tlv_encode(67, 'chainload.kpxe' + chr(0)) # chainload iPXE
            if opt53 == 5: # ACK
                self.leases[client_mac]['ipxe'] = False
        if self.mode_proxy:
            response += self.tlv_encode(60, 'PXEClient')
            response += struct.pack('!BBBBBBB4sB', 43, 10, 6, 1, 0b1000, 10, 4, chr(0) + 'PXE', 0xff)
        response += '\xff'
        return response

    def dhcp_offer(self, message):
        '''This method responds to DHCP discovery with offer.'''
        client_mac, header_response = self.craft_header(message)
        options_response = self.craft_options(2, client_mac) # DHCPOFFER
        response = header_response + options_response
        self.sock.sendto(response, (self.broadcast, 68))

    def dhcp_ack(self, message):
        '''This method responds to DHCP request with acknowledge.'''
        client_mac, header_response = self.craft_header(message)
        options_response = self.craft_options(5, client_mac) # DHCPACK
        response = header_response + options_response
        self.sock.sendto(response, (self.broadcast, 68))

    def validate_req(self):
        return False

    def run(self):
        '''Main listen loop.'''
        while self.LoopDhcpStatus:
            message, address = self.sock.recvfrom(1024)
            # 28 bytes of padding
            # 6 bytes MAC to string.
            [client_mac] = struct.unpack('!28x6s', message[:34])                # Get MAC address
            self.leases[client_mac]['options'] = self.tlv_parse(message[240:])
            type = ord(self.leases[client_mac]['options'][53][0])               # see RFC2131, page 10
            if type == 1:
                try:
                    self.dhcp_offer(message)
                    self.sendConnetedClient.emit({
                        'ip_addr': self.leases[client_mac]['ip'],
                        'host_name': self.leases[client_mac]['options'][12][0],
                        'mac_addr': self.get_mac([client_mac][0]).lower(),
                    })
                except OutOfLeasesError:
                    pass
            elif type == 3 and address[0] == '0.0.0.0' and not self.mode_proxy:
                self.dhcp_ack(message)
            elif type == 3 and address[0] != '0.0.0.0' and self.mode_proxy:
                self.dhcp_ack(message)

    def stop(self):
        self.LoopDhcpStatus = False


