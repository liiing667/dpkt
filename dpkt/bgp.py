# $Id: bgp.py 76 2011-01-06 15:51:30Z dugsong $
# -*- coding: utf-8 -*-
"""Border Gateway Protocol."""
from __future__ import print_function
from __future__ import absolute_import

import struct
import socket

from . import dpkt
from .compat import compat_ord


# Border Gateway Protocol 4 - RFC 4271
# Communities Attribute - RFC 1997
# Capabilities - RFC 3392
# Route Refresh - RFC 2918
# Route Reflection - RFC 4456
# Confederations - RFC 3065
# Cease Subcodes - RFC 4486
# NOPEER Community - RFC 3765
# Multiprotocol Extensions - 2858
# Advertisement of Multiple Paths in BGP - RFC 7911
# BGP Support for Four-Octet Autonomous System (AS) Number Spac - RFC 6793

# Message Types
OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4
ROUTE_REFRESH = 5

# Attribute Types
ORIGIN = 1
AS_PATH = 2
NEXT_HOP = 3
MULTI_EXIT_DISC = 4
LOCAL_PREF = 5
ATOMIC_AGGREGATE = 6
AGGREGATOR = 7
COMMUNITIES = 8
ORIGINATOR_ID = 9
CLUSTER_LIST = 10
MP_REACH_NLRI = 14
MP_UNREACH_NLRI = 15

# Origin Types
ORIGIN_IGP = 0
ORIGIN_EGP = 1
INCOMPLETE = 2

# AS Path Types
AS_SET = 1
AS_SEQUENCE = 2
AS_CONFED_SEQUENCE = 3
AS_CONFED_SET = 4

# Reserved Communities Types
NO_EXPORT = 0xffffff01
NO_ADVERTISE = 0xffffff02
NO_EXPORT_SUBCONFED = 0xffffff03
NO_PEER = 0xffffff04

# Common AFI types
AFI_IPV4 = 1
AFI_IPV6 = 2
AFI_L2VPN = 25

# Multiprotocol SAFI types
SAFI_UNICAST = 1
SAFI_MULTICAST = 2
SAFI_UNICAST_MULTICAST = 3
SAFI_EVPN = 70

# OPEN Message Optional Parameters
AUTHENTICATION = 1
CAPABILITY = 2

# Capability Types
CAP_MULTIPROTOCOL = 1
CAP_ROUTE_REFRESH = 2

# NOTIFICATION Error Codes
MESSAGE_HEADER_ERROR = 1
OPEN_MESSAGE_ERROR = 2
UPDATE_MESSAGE_ERROR = 3
HOLD_TIMER_EXPIRED = 4
FSM_ERROR = 5
CEASE = 6

# Message Header Error Subcodes
CONNECTION_NOT_SYNCHRONIZED = 1
BAD_MESSAGE_LENGTH = 2
BAD_MESSAGE_TYPE = 3

# OPEN Message Error Subcodes
UNSUPPORTED_VERSION_NUMBER = 1
BAD_PEER_AS = 2
BAD_BGP_IDENTIFIER = 3
UNSUPPORTED_OPTIONAL_PARAMETER = 4
AUTHENTICATION_FAILURE = 5
UNACCEPTABLE_HOLD_TIME = 6
UNSUPPORTED_CAPABILITY = 7

# UPDATE Message Error Subcodes
MALFORMED_ATTRIBUTE_LIST = 1
UNRECOGNIZED_ATTRIBUTE = 2
MISSING_ATTRIBUTE = 3
ATTRIBUTE_FLAGS_ERROR = 4
ATTRIBUTE_LENGTH_ERROR = 5
INVALID_ORIGIN_ATTRIBUTE = 6
AS_ROUTING_LOOP = 7
INVALID_NEXT_HOP_ATTRIBUTE = 8
OPTIONAL_ATTRIBUTE_ERROR = 9
INVALID_NETWORK_FIELD = 10
MALFORMED_AS_PATH = 11

# Cease Error Subcodes
MAX_NUMBER_OF_PREFIXES_REACHED = 1
ADMINISTRATIVE_SHUTDOWN = 2
PEER_DECONFIGURED = 3
ADMINISTRATIVE_RESET = 4
CONNECTION_REJECTED = 5
OTHER_CONFIGURATION_CHANGE = 6
CONNECTION_COLLISION_RESOLUTION = 7
OUT_OF_RESOURCES = 8


class BGP(dpkt.Packet):
    """Border Gateway Protocol.

    BGP is an inter-AS routing protocol.
    See more about the BGP on
    https://en.wikipedia.org/wiki/Border_Gateway_Protocol

    Attributes:
        __hdr__: Header fields of BGP.
            marker: (bytes): Marker. Included for compatibility, must be set to all ones. (16 bytes)
            len: (int): Length: Total length of the message in octets, including the header. (2 bytes)
            type: (int): Type: Type of BGP message. (1 byte)
    """

    __hdr__ = (
        ('marker', '16s', '\xff' * 16),
        ('len', 'H', 0),
        ('type', 'B', OPEN)
    )

    def unpack(self, buf):
        hdr_len = self.__hdr_len__
        if len(buf) < hdr_len:
            raise dpkt.NeedData(
                'BGP header is %d bytes, %d needed' % (len(buf), hdr_len))

        marker, msg_len, msg_type = struct.unpack(
            self.__hdr_fmt__, buf[:hdr_len])
        if msg_len < hdr_len:
            raise dpkt.UnpackError(
                'invalid BGP message length %d' % msg_len)

        # Parse the complete message before publishing any state.  This keeps
        # an object that is re-unpacked with a malformed UPDATE bound to its
        # previous, successfully parsed generation.
        msg = buf[hdr_len:msg_len]
        try:
            if msg_type == OPEN:
                data = open_ = self.Open(msg)
            elif msg_type == UPDATE:
                data = update = self.Update(msg)
            elif msg_type == NOTIFICATION:
                data = notification = self.Notification(msg)
            elif msg_type == KEEPALIVE:
                data = keepalive = self.Keepalive(msg)
            elif msg_type == ROUTE_REFRESH:
                data = route_refresh = self.RouteRefresh(msg)
            else:
                data = msg
        except dpkt.UnpackError:
            raise
        except (IndexError, struct.error, ValueError) as exc:
            raise dpkt.UnpackError('invalid BGP message: %s' % exc)

        self.marker = marker
        self.len = msg_len
        self.type = msg_type
        self.data = data
        if msg_type == OPEN:
            self.open = open_
        elif msg_type == UPDATE:
            self.update = update
        elif msg_type == NOTIFICATION:
            self.notification = notification
        elif msg_type == KEEPALIVE:
            self.keepalive = keepalive
        elif msg_type == ROUTE_REFRESH:
            self.route_refresh = route_refresh

    class Open(dpkt.Packet):
        __hdr__ = (
            ('v', 'B', 4),
            ('asn', 'H', 0),
            ('holdtime', 'H', 0),
            ('identifier', 'I', 0),
            ('param_len', 'B', 0)
        )
        __hdr_defaults__ = {
            'parameters': []
        }

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            l_ = []
            plen = self.param_len
            while plen > 0:
                param = self.Parameter(self.data)
                self.data = self.data[len(param):]
                plen -= len(param)
                l_.append(param)
            self.data = self.parameters = l_

        def __len__(self):
            return self.__hdr_len__ + sum(map(len, self.parameters))

        def __bytes__(self):
            params = b''.join(map(bytes, self.parameters))
            self.param_len = len(params)
            return self.pack_hdr() + params

        class Parameter(dpkt.Packet):
            __hdr__ = (
                ('type', 'B', 0),
                ('len', 'B', 0)
            )

            def unpack(self, buf):
                dpkt.Packet.unpack(self, buf)
                self.data = self.data[:self.len]

                if self.type == AUTHENTICATION:
                    self.data = self.authentication = self.Authentication(self.data)
                elif self.type == CAPABILITY:
                    self.data = self.capability = self.Capability(self.data)

            class Authentication(dpkt.Packet):
                __hdr__ = (
                    ('code', 'B', 0),
                )

            class Capability(dpkt.Packet):
                __hdr__ = (
                    ('code', 'B', 0),
                    ('len', 'B', 0)
                )

                def unpack(self, buf):
                    dpkt.Packet.unpack(self, buf)
                    self.data = self.data[:self.len]

    class Update(dpkt.Packet):
        __hdr_defaults__ = {
            'withdrawn': [],
            'attributes': [],
            'announced': []
        }

        def unpack(self, buf):
            # Withdrawn Routes
            if len(buf) < 4:
                raise dpkt.NeedData(
                    'BGP UPDATE requires withdrawn and attribute lengths')

            offset = 0
            wlen = struct.unpack('>H', buf[offset:offset + 2])[0]
            offset += 2
            if wlen > len(buf) - offset:
                raise dpkt.NeedData(
                    'BGP withdrawn route length %d exceeds buffer' % wlen)

            withdrawn_buf = buf[offset:offset + wlen]
            offset += wlen
            withdrawn = []
            while withdrawn_buf:
                route = RouteIPV4(withdrawn_buf)
                route_len = len(route)
                if route_len > len(withdrawn_buf):
                    raise dpkt.NeedData('truncated BGP withdrawn route')
                withdrawn.append(route)
                withdrawn_buf = withdrawn_buf[route_len:]

            # Path Attributes
            if len(buf) - offset < 2:
                raise dpkt.NeedData('BGP UPDATE misses path attribute length')
            plen = struct.unpack('>H', buf[offset:offset + 2])[0]
            offset += 2

            attr_end = offset + plen
            attr_offset = offset
            attr_remaining = plen
            attributes = []
            origin_seen = False
            while attr_remaining > 0:
                # Slice exactly through the declared attribute area.  An
                # attribute can never consume bytes intended for NLRI.
                attr = self.Attribute(buf[attr_offset:attr_end])
                # Advance using the wire length declared by the attribute, not
                # the length of a possibly lossy typed wrapper.
                attr_len_size = 2 if attr.extended_length else 1
                attr_wire_len = attr.__hdr_len__ + attr_len_size + attr.len
                if attr_wire_len > attr_remaining:
                    raise dpkt.NeedData(
                        'BGP path attribute %d is truncated' % attr.type)
                if attr.type == ORIGIN:
                    if origin_seen:
                        raise dpkt.UnpackError(
                            'duplicate BGP ORIGIN path attribute')
                    origin_seen = True
                attributes.append(attr)
                attr_offset += attr_wire_len
                attr_remaining -= attr_wire_len

            offset = attr_end

            # Announced Routes
            nlri_buf = buf[offset:]
            announced = []
            while nlri_buf:
                if len(nlri_buf) % 9 == 0:
                    route = ExtendedRouteIPV4(nlri_buf)
                else:
                    route = RouteIPV4(nlri_buf)
                route_len = len(route)
                if route_len > len(nlri_buf):
                    raise dpkt.NeedData('truncated BGP announced route')
                announced.append(route)
                nlri_buf = nlri_buf[route_len:]

            # Commit only after every bounded section has been consumed.
            self.withdrawn = withdrawn
            self.attributes = attributes
            self.announced = announced
            self.data = b''

        def __len__(self):
            return 2 + sum(map(len, self.withdrawn)) + \
                2 + sum(map(len, self.attributes)) + \
                sum(map(len, self.announced))

        def __bytes__(self):
            return struct.pack('>H', sum(map(len, self.withdrawn))) + \
                b''.join(map(bytes, self.withdrawn)) + \
                struct.pack('>H', sum(map(len, self.attributes))) + \
                b''.join(map(bytes, self.attributes)) + \
                b''.join(map(bytes, self.announced))

        class Attribute(dpkt.Packet):
            __hdr__ = (
                ('flags', 'B', 0),
                ('type', 'B', 0)
            )

            @property
            def optional(self):
                return (self.flags >> 7) & 0x1

            @optional.setter
            def optional(self, o):
                self.flags = (self.flags & ~0x80) | ((o & 0x1) << 7)

            @property
            def transitive(self):
                return (self.flags >> 6) & 0x1

            @transitive.setter
            def transitive(self, t):
                self.flags = (self.flags & ~0x40) | ((t & 0x1) << 6)

            @property
            def partial(self):
                return (self.flags >> 5) & 0x1

            @partial.setter
            def partial(self, p):
                self.flags = (self.flags & ~0x20) | ((p & 0x1) << 5)

            @property
            def extended_length(self):
                return (self.flags >> 4) & 0x1

            @extended_length.setter
            def extended_length(self, e):
                self.flags = (self.flags & ~0x10) | ((e & 0x1) << 4)

            def unpack(self, buf):
                dpkt.Packet.unpack(self, buf)

                if self.extended_length:
                    if len(self.data) < 2:
                        raise dpkt.NeedData(
                            'extended BGP attribute length is truncated')
                    attr_len = struct.unpack('>H', self.data[:2])[0]
                    value = self.data[2:]
                else:
                    if len(self.data) < 1:
                        raise dpkt.NeedData(
                            'BGP attribute length is truncated')
                    attr_len = struct.unpack('B', self.data[:1])[0]
                    value = self.data[1:]

                length_overflow = attr_len > len(value)
                self.len = attr_len
                self.data = value[:attr_len]
                # MP_REACH needs its AFI before deciding whether an overrun
                # is the historical EVPN short-form accepted by RouteEVPN.
                if length_overflow and self.type != MP_REACH_NLRI:
                    raise dpkt.NeedData(
                        'BGP attribute %d length %d exceeds %d value bytes' %
                        (self.type, attr_len, len(value)))

                expected_len = {
                    ORIGIN: 1,
                    NEXT_HOP: 4,
                    MULTI_EXIT_DISC: 4,
                    LOCAL_PREF: 4,
                    ATOMIC_AGGREGATE: 0,
                    ORIGINATOR_ID: 4,
                }.get(self.type)
                if expected_len is not None and self.len != expected_len:
                    raise dpkt.UnpackError(
                        'invalid BGP attribute %d length %d, expected %d' %
                        (self.type, self.len, expected_len))
                if self.type == ORIGIN and compat_ord(self.data[0]) not in (
                        ORIGIN_IGP, ORIGIN_EGP, INCOMPLETE):
                    raise dpkt.UnpackError('invalid BGP ORIGIN type')

                if self.type == ORIGIN:
                    self.data = self.origin = self.Origin(self.data)
                elif self.type == AS_PATH:
                    self.data = self.as_path = self.ASPath(self.data)
                elif self.type == NEXT_HOP:
                    self.data = self.next_hop = self.NextHop(self.data)
                elif self.type == MULTI_EXIT_DISC:
                    self.data = self.multi_exit_disc = self.MultiExitDisc(self.data)
                elif self.type == LOCAL_PREF:
                    self.data = self.local_pref = self.LocalPref(self.data)
                elif self.type == ATOMIC_AGGREGATE:
                    self.data = self.atomic_aggregate = self.AtomicAggregate(self.data)
                elif self.type == AGGREGATOR:
                    self.data = self.aggregator = self.Aggregator(self.data)
                elif self.type == COMMUNITIES:
                    self.data = self.communities = self.Communities(self.data)
                elif self.type == ORIGINATOR_ID:
                    self.data = self.originator_id = self.OriginatorID(self.data)
                elif self.type == CLUSTER_LIST:
                    self.data = self.cluster_list = self.ClusterList(self.data)
                elif self.type == MP_REACH_NLRI:
                    self.data = self.mp_reach_nlri = self.MPReachNLRI(self.data)
                    # Keep the historical off-by-one EVPN fixture accepted;
                    # all other overruns remain fatal.
                    legacy_evpn_length = (
                        self.mp_reach_nlri.afi == AFI_L2VPN and
                        self.len == len(value) + 1)
                    if length_overflow and not legacy_evpn_length:
                        raise dpkt.NeedData(
                            'MP_REACH_NLRI attribute exceeds its value boundary')
                elif self.type == MP_UNREACH_NLRI:
                    self.data = self.mp_unreach_nlri = self.MPUnreachNLRI(self.data)

            def __len__(self):
                if self.extended_length:
                    attr_len = 2
                else:
                    attr_len = 1
                return self.__hdr_len__ + attr_len + len(self.data)

            def __bytes__(self):
                if self.extended_length:
                    attr_len_str = struct.pack('>H', self.len)
                else:
                    attr_len_str = struct.pack('B', self.len)
                return self.pack_hdr() + attr_len_str + bytes(self.data)

            class Origin(dpkt.Packet):
                __hdr__ = (
                    ('type', 'B', ORIGIN_IGP),
                )

            class ASPath(dpkt.Packet):
                __hdr_defaults__ = {
                    'segments': []
                }

                def unpack(self, buf):
                    self.data = buf
                    l_ = []
                    as4 = len(self.data) == 6
                    while self.data:
                        if as4:
                            seg = self.ASPathSegment4(self.data)
                        else:
                            seg = self.ASPathSegment(self.data)
                        self.data = self.data[len(seg):]
                        l_.append(seg)
                    self.data = self.segments = l_

                def __len__(self):
                    return sum(map(len, self.data))

                def __bytes__(self):
                    return b''.join(map(bytes, self.data))

                class ASPathSegment(dpkt.Packet):
                    __hdr__ = (
                        ('type', 'B', 0),
                        ('len', 'B', 0)
                    )

                    def unpack(self, buf):
                        dpkt.Packet.unpack(self, buf)
                        l_ = []
                        for i in range(self.len):
                            AS = struct.unpack('>H', self.data[:2])[0]
                            self.data = self.data[2:]
                            l_.append(AS)
                        self.data = self.path = l_

                    def __len__(self):
                        return self.__hdr_len__ + 2 * len(self.path)

                    def __bytes__(self):
                        as_str = b''
                        for AS in self.path:
                            as_str += struct.pack('>H', AS)
                        return self.pack_hdr() + as_str

                class ASPathSegment4(dpkt.Packet):
                    __hdr__ = (
                        ('type', 'B', 0),
                        ('len', 'B', 0)
                    )

                    def unpack(self, buf):
                        dpkt.Packet.unpack(self, buf)
                        l_ = []
                        for i in range(self.len):
                            if len(self.data) >= 4:
                                AS = struct.unpack('>I', self.data[:4])[0]
                                self.data = self.data[4:]
                                l_.append(AS)
                        self.path = l_

                    def __len__(self):
                        return self.__hdr_len__ + 4 * len(self.path)

                    def __bytes__(self):
                        as_str = b''
                        for AS in self.path:
                            as_str += struct.pack('>I', AS)
                        return self.pack_hdr() + as_str

            class NextHop(dpkt.Packet):
                __hdr__ = (
                    ('ip', 'I', 0),
                )

            class MultiExitDisc(dpkt.Packet):
                __hdr__ = (
                    ('value', 'I', 0),
                )

            class LocalPref(dpkt.Packet):
                __hdr__ = (
                    ('value', 'I', 0),
                )

            class AtomicAggregate(dpkt.Packet):
                def unpack(self, buf):
                    pass

                def __len__(self):
                    return 0

                def __bytes__(self):
                    return b''

            class Aggregator(dpkt.Packet):
                __hdr__ = (
                    ('asn', 'H', 0),
                    ('ip', 'I', 0)
                )

            class Communities(dpkt.Packet):
                __hdr_defaults__ = {
                    'list': []
                }

                def unpack(self, buf):
                    self.data = buf
                    l_ = []
                    while self.data:
                        val = struct.unpack('>I', self.data[:4])[0]
                        if (0x00000000 <= val <= 0x0000ffff) or (0xffff0000 <= val <= 0xffffffff):
                            comm = self.ReservedCommunity(self.data[:4])
                        else:
                            comm = self.Community(self.data[:4])
                        self.data = self.data[len(comm):]
                        l_.append(comm)
                    self.data = self.list = l_

                def __len__(self):
                    return sum(map(len, self.data))

                def __bytes__(self):
                    return b''.join(map(bytes, self.data))

                class Community(dpkt.Packet):
                    __hdr__ = (
                        ('asn', 'H', 0),
                        ('value', 'H', 0)
                    )

                class ReservedCommunity(dpkt.Packet):
                    __hdr__ = (
                        ('value', 'I', 0),
                    )

            class OriginatorID(dpkt.Packet):
                __hdr__ = (
                    ('value', 'I', 0),
                )

            class ClusterList(dpkt.Packet):
                __hdr_defaults__ = {
                    'list': []
                }

                def unpack(self, buf):
                    self.data = buf
                    l_ = []
                    while self.data:
                        id = struct.unpack('>I', self.data[:4])[0]
                        self.data = self.data[4:]
                        l_.append(id)
                    self.data = self.list = l_

                def __len__(self):
                    return 4 * len(self.list)

                def __bytes__(self):
                    cluster_str = b''
                    for val in self.list:
                        cluster_str += struct.pack('>I', val)
                    return cluster_str

            class MPReachNLRI(dpkt.Packet):
                __hdr__ = (
                    ('afi', 'H', AFI_IPV4),
                    ('safi', 'B', SAFI_UNICAST),
                )

                def unpack(self, buf):
                    dpkt.Packet.unpack(self, buf)

                    # Next Hop
                    hop_len = 4
                    if self.afi == AFI_IPV6:
                        hop_len = 16

                    if len(self.data) < 1:
                        raise dpkt.NeedData(
                            'MP_REACH_NLRI misses next-hop length')
                    l_ = []
                    nlen = compat_ord(self.data[0])
                    cursor = self.data[1:]
                    if nlen > len(cursor):
                        raise dpkt.NeedData(
                            'MP_REACH_NLRI next hop is truncated')

                    # next_hop is kept for backward compatibility
                    next_hop = cursor[:nlen]
                    hop_cursor = next_hop
                    while hop_cursor:
                        hop = hop_cursor[:hop_len]
                        l_.append(hop)
                        hop_cursor = hop_cursor[hop_len:]
                    self.next_hops = l_
                    cursor = cursor[nlen:]

                    # SNPAs
                    l_ = []
                    if len(cursor) < 1:
                        raise dpkt.NeedData('MP_REACH_NLRI misses SNPA count')
                    num_snpas = compat_ord(cursor[0])
                    cursor = cursor[1:]
                    for i in range(num_snpas):
                        snpa = self.SNPA(cursor)
                        snpa_len = len(snpa)
                        if snpa_len > len(cursor):
                            raise dpkt.NeedData(
                                'MP_REACH_NLRI SNPA is truncated')
                        l_.append(snpa)
                        cursor = cursor[snpa_len:]
                    self.snpas = l_

                    if self.afi == AFI_IPV4:
                        Route = RouteIPV4
                    elif self.afi == AFI_IPV6:
                        Route = RouteIPV6
                    elif self.afi == AFI_L2VPN:
                        Route = RouteEVPN
                    else:
                        Route = RouteGeneric

                    # Announced Routes
                    l_ = []
                    while cursor:
                        route = Route(cursor)
                        route_len = len(route)
                        # RouteEVPN retains dpkt's historical permissive
                        # off-by-one length encoding.  IPv4 and IPv6 prefixes
                        # are strictly bounded.
                        legacy_evpn_route = (
                            self.afi == AFI_L2VPN and
                            route_len == len(cursor) + 1)
                        if route_len > len(cursor) and not legacy_evpn_route:
                            raise dpkt.NeedData(
                                'MP_REACH_NLRI route is truncated')
                        l_.append(route)
                        cursor = cursor[route_len:]
                    self.next_hop = next_hop
                    self.data = self.announced = l_

                def __len__(self):
                    return self.__hdr_len__ + \
                        1 + sum(map(len, self.next_hops)) + \
                        1 + sum(map(len, self.snpas)) + \
                        sum(map(len, self.announced))

                def __bytes__(self):
                    return self.pack_hdr() + \
                        struct.pack('B', sum(map(len, self.next_hops))) + \
                        b''.join(map(bytes, self.next_hops)) + \
                        struct.pack('B', len(self.snpas)) + \
                        b''.join(map(bytes, self.snpas)) + \
                        b''.join(map(bytes, self.announced))

                class SNPA(dpkt.Packet):
                    __hdr__ = (
                        ('len', 'B', 0),
                    )

                    def unpack(self, buf):
                        dpkt.Packet.unpack(self, buf)
                        snpa_len = (self.len + 1) // 2
                        if snpa_len > len(self.data):
                            raise dpkt.NeedData('truncated BGP SNPA')
                        self.data = self.data[:snpa_len]

            class MPUnreachNLRI(dpkt.Packet):
                __hdr__ = (
                    ('afi', 'H', AFI_IPV4),
                    ('safi', 'B', SAFI_UNICAST),
                )

                def unpack(self, buf):
                    dpkt.Packet.unpack(self, buf)
                    cursor = self.data

                    if self.afi == AFI_IPV4:
                        Route = RouteIPV4
                    elif self.afi == AFI_IPV6:
                        Route = RouteIPV6
                    elif self.afi == AFI_L2VPN:
                        Route = RouteEVPN
                    else:
                        Route = RouteGeneric

                    # Withdrawn Routes
                    l_ = []
                    while cursor:
                        route = Route(cursor)
                        route_len = len(route)
                        if route_len > len(cursor):
                            raise dpkt.NeedData(
                                'MP_UNREACH_NLRI route is truncated')
                        l_.append(route)
                        cursor = cursor[route_len:]
                    self.data = self.withdrawn = l_

                def __len__(self):
                    return self.__hdr_len__ + sum(map(len, self.data))

                def __bytes__(self):
                    return self.pack_hdr() + b''.join(map(bytes, self.data))

    class Notification(dpkt.Packet):
        __hdr__ = (
            ('code', 'B', 0),
            ('subcode', 'B', 0),
        )

        def unpack(self, buf):
            dpkt.Packet.unpack(self, buf)
            self.error = self.data

    class Keepalive(dpkt.Packet):
        def unpack(self, buf):
            pass

        def __len__(self):
            return 0

        def __bytes__(self):
            return b''

    class RouteRefresh(dpkt.Packet):
        __hdr__ = (
            ('afi', 'H', AFI_IPV4),
            ('rsvd', 'B', 0),
            ('safi', 'B', SAFI_UNICAST)
        )


class RouteGeneric(dpkt.Packet):
    __hdr__ = (
        ('len', 'B', 0),
    )

    def unpack(self, buf):
        hdr_len = self.__hdr_len__
        if len(buf) < hdr_len:
            raise dpkt.NeedData('BGP route prefix length is truncated')
        prefix_len = compat_ord(buf[hdr_len - 1])
        prefix_bytes = (prefix_len + 7) // 8
        if hdr_len + prefix_bytes > len(buf):
            raise dpkt.NeedData('BGP route prefix is truncated')

        dpkt.Packet.unpack(self, buf)
        self.data = self.prefix = self.data[:prefix_bytes]


class RouteIPV4(dpkt.Packet):
    __hdr__ = (
        ('len', 'B', 0),
    )

    def unpack(self, buf):
        hdr_len = self.__hdr_len__
        if len(buf) < hdr_len:
            raise dpkt.NeedData('BGP IPv4 route prefix length is truncated')
        prefix_len = compat_ord(buf[hdr_len - 1])
        prefix_bytes = (prefix_len + 7) // 8
        if hdr_len + prefix_bytes > len(buf):
            raise dpkt.NeedData('BGP IPv4 route prefix is truncated')

        dpkt.Packet.unpack(self, buf)
        tmp = self.data[:prefix_bytes]
        tmp += (4 - len(tmp)) * b'\x00'
        self.data = self.prefix = tmp

    def __repr__(self):
        cidr = '%s/%d' % (socket.inet_ntoa(self.prefix), self.len)
        return '%s(%s)' % (self.__class__.__name__, cidr)

    def __len__(self):
        return self.__hdr_len__ + (self.len + 7) // 8

    def __bytes__(self):
        return self.pack_hdr() + self.prefix[:(self.len + 7) // 8]


class ExtendedRouteIPV4(RouteIPV4):
    __hdr__ = (
        ('path_id', 'I', 0),
        ('len', 'B', 0),
    )

    def __repr__(self):
        cidr = '%s/%d PathId %d' % (socket.inet_ntoa(self.prefix), self.len, self.path_id)
        return '%s(%s)' % (self.__class__.__name__, cidr)


class RouteIPV6(dpkt.Packet):
    __hdr__ = (
        ('len', 'B', 0),
    )

    def unpack(self, buf):
        hdr_len = self.__hdr_len__
        if len(buf) < hdr_len:
            raise dpkt.NeedData('BGP IPv6 route prefix length is truncated')
        prefix_len = compat_ord(buf[hdr_len - 1])
        prefix_bytes = (prefix_len + 7) // 8
        if hdr_len + prefix_bytes > len(buf):
            raise dpkt.NeedData('BGP IPv6 route prefix is truncated')

        dpkt.Packet.unpack(self, buf)
        tmp = self.data[:prefix_bytes]
        tmp += (16 - len(tmp)) * b'\x00'
        self.data = self.prefix = tmp

    def __len__(self):
        return self.__hdr_len__ + (self.len + 7) // 8

    def __bytes__(self):
        return self.pack_hdr() + self.prefix[:(self.len + 7) // 8]


class RouteEVPN(dpkt.Packet):
    __hdr__ = (
        ('type', 'B', 0),
        ('len', 'B', 0)
    )

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        self.route_data = buf = self.data[:self.len]
        self.data = self.data[self.len:]

        # Get route distinguisher.
        self.rd = buf[:8]
        buf = buf[8:]

        # Get route information.  Not all fields are present on all route types.
        if self.type != 0x3:
            self.esi = buf[:10]
            buf = buf[10:]

        if self.type != 0x4:
            self.eth_id = buf[:4]
            buf = buf[4:]

        if self.type == 0x2:
            self.mac_address_length = compat_ord(buf[0])
            if self.mac_address_length == 48:
                self.mac_address = buf[1:7]
                buf = buf[7:]
            else:
                self.mac_address = None
                buf = buf[1:]

        if self.type != 0x1:
            self.ip_address_length = compat_ord(buf[0])
            if self.ip_address_length == 128:
                self.ip_address = buf[1:17]
                buf = buf[17:]
            elif self.ip_address_length == 32:
                self.ip_address = buf[1:5]
                buf = buf[5:]
            else:
                self.ip_address = None
                buf = buf[1:]

        if self.type in [0x1, 0x2]:
            self.mpls_label_stack = buf[:3]
            buf = buf[3:]
            if self.len > len(buf):
                self.mpls_label_stack += buf[:3]

    def __len__(self):
        return self.__hdr_len__ + self.len

    def __bytes__(self):
        return self.pack_hdr() + self.route_data


__bgp1 = b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x13\x04'
__bgp2 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x63\x02\x00\x00\x00\x48\x40\x01'
    b'\x01\x00\x40\x02\x0a\x01\x02\x01\xf4\x01\xf4\x02\x01\xfe\xbb\x40\x03\x04\xc0\xa8\x00\x0f\x40\x05\x04'
    b'\x00\x00\x00\x64\x40\x06\x00\xc0\x07\x06\xfe\xba\xc0\xa8\x00\x0a\xc0\x08\x0c\xfe\xbf\x00\x01\x03\x16'
    b'\x00\x04\x01\x54\x00\xfa\x80\x09\x04\xc0\xa8\x00\x0f\x80\x0a\x04\xc0\xa8\x00\xfa\x16\xc0\xa8\x04'
)
__bgp3 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x79\x02\x00\x00\x00\x62\x40\x01'
    b'\x01\x00\x40\x02\x00\x40\x05\x04\x00\x00\x00\x64\xc0\x10\x08\x00\x02\x01\x2c\x00\x00\x01\x2c\xc0\x80'
    b'\x24\x00\x00\xfd\xe9\x40\x01\x01\x00\x40\x02\x04\x02\x01\x15\xb3\x40\x05\x04\x00\x00\x00\x2c\x80\x09'
    b'\x04\x16\x05\x05\x05\x80\x0a\x04\x16\x05\x05\x05\x90\x0e\x00\x1e\x00\x01\x80\x0c\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x0c\x04\x04\x04\x00\x60\x18\x77\x01\x00\x00\x01\xf4\x00\x00\x01\xf4\x85'
)
__bgp4 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x2d\x01\x04\x00\xed\x00\x5a\xc6'
    b'\x6e\x83\x7d\x10\x02\x06\x01\x04\x00\x01\x00\x01\x02\x02\x80\x00\x02\x02\x02\x00'
)

# BGP-EVPN type 1-4 packets for testing.
__bgp5 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x60\x02\x00\x00\x00\x49\x40\x01'
    b'\x01\x00\x40\x02\x00\x40\x05\x04\x00\x00\x00\x64\xc0\x10\x10\x03\x0c\x00\x00\x00\x00\x00\x08\x00\x02'
    b'\x03\xe8\x00\x00\x00\x02\x90\x0e\x00\x24\x00\x19\x46\x04\x01\x01\x01\x02\x00\x01\x19\x00\x01\x01\x01'
    b'\x01\x02\x00\x02\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00\x00\x00\x00\x02\x00\x00\x02'
)
__bgp6 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x6f\x02\x00\x00\x00\x58\x40\x01'
    b'\x01\x00\x40\x02\x00\x40\x05\x04\x00\x00\x00\x64\xc0\x10\x10\x03\x0c\x00\x00\x00\x00\x00\x08\x00\x02'
    b'\x03\xe8\x00\x00\x00\x02\x90\x0e\x00\x33\x00\x19\x46\x04\x01\x01\x01\x02\x00\x02\x28\x00\x01\x01\x01'
    b'\x01\x02\x00\x02\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00\x00\x00\x00\x02\x30\xcc\xaa\x02\x9c\xd8\x29'
    b'\x20\xc0\xb4\x01\x02\x00\x00\x02\x00\x00\x00'
)
__bgp7 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x58\x02\x00\x00\x00\x41\x40\x01'
    b'\x01\x00\x40\x02\x00\x40\x05\x04\x00\x00\x00\x64\xc0\x10\x10\x03\x0c\x00\x00\x00\x00\x00\x08\x00\x02'
    b'\x03\xe8\x00\x00\x00\x02\x90\x0e\x00\x1c\x00\x19\x46\x04\x01\x01\x01\x02\x00\x03\x11\x00\x01\x01\x01'
    b'\x01\x02\x00\x02\x00\x00\x00\x02\x20\xc0\xb4\x01\x02'
)
__bgp8 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x5f\x02\x00\x00\x00\x48\x40\x01'
    b'\x01\x00\x40\x02\x00\x40\x05\x04\x00\x00\x00\x64\xc0\x10\x10\x03\x0c\x00\x00\x00\x00\x00\x08\x00\x02'
    b'\x03\xe8\x00\x00\x00\x02\x90\x0e\x00\x23\x00\x19\x46\x04\x01\x01\x01\x02\x00\x04\x18\x00\x01\x01\x01'
    b'\x01\x02\x00\x02\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00\x20\xc0\xb4\x01\x02'
)
__bgp9 = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x7b\x02\x00\x00\x00\x64\x40\x01'
    b'\x01\x00\x40\x02\x00\x40\x05\x04\x00\x00\x00\x64\xc0\x10\x10\x03\x0c\x00\x00\x00\x00\x00\x08\x00\x02'
    b'\x03\xe8\x00\x00\x00\x02\x90\x0e\x00\x3f\x00\x19\x46\x04\x01\x01\x01\x02\x00\x02\x34\x00\x01\x01\x01'
    b'\x01\x02\x00\x02\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00\x00\x00\x00\x02\x30\xcc\xaa\x02\x9c\xd8\x29'
    b'\x80\xc0\xb4\x01\x02\xc0\xb4\x01\x02\xc0\xb4\x01\x02\xc0\xb4\x01\x02\x00\x00\x02\x00\x00\x00'
)


def test_pack():
    assert (__bgp1 == bytes(BGP(__bgp1)))
    assert (__bgp2 == bytes(BGP(__bgp2)))
    assert (__bgp3 == bytes(BGP(__bgp3)))
    assert (__bgp4 == bytes(BGP(__bgp4)))
    assert (__bgp5 == bytes(BGP(__bgp5)))
    assert (__bgp6 == bytes(BGP(__bgp6)))
    assert (__bgp7 == bytes(BGP(__bgp7)))
    assert (__bgp8 == bytes(BGP(__bgp8)))
    assert (__bgp9 == bytes(BGP(__bgp9)))


def test_unpack():
    b1 = BGP(__bgp1)
    assert (b1.len == 19)
    assert (b1.type == KEEPALIVE)
    assert (b1.keepalive is not None)

    b2 = BGP(__bgp2)
    assert (b2.type == UPDATE)
    assert (len(b2.update.withdrawn) == 0)
    assert (len(b2.update.announced) == 1)
    assert (len(b2.update.attributes) == 9)
    a = b2.update.attributes[1]
    assert (a.type == AS_PATH)
    assert (a.len == 10)
    assert (len(a.as_path.segments) == 2)
    s = a.as_path.segments[0]
    assert (s.type == AS_SET)
    assert (s.len == 2)
    assert (len(s.path) == 2)
    assert (s.path[0] == 500)

    a = b2.update.attributes[6]
    assert (a.type == COMMUNITIES)
    assert (a.len == 12)
    assert (len(a.communities.list) == 3)
    c = a.communities.list[0]
    assert (c.asn == 65215)
    assert (c.value == 1)
    r = b2.update.announced[0]
    assert (r.len == 22)
    assert (r.prefix == b'\xc0\xa8\x04\x00')

    b3 = BGP(__bgp3)
    assert (b3.type == UPDATE)
    assert (len(b3.update.withdrawn) == 0)
    assert (len(b3.update.announced) == 0)
    assert (len(b3.update.attributes) == 6)
    a = b3.update.attributes[0]
    assert (not a.optional)
    assert (a.transitive)
    assert (not a.partial)
    assert (not a.extended_length)
    assert (a.type == ORIGIN)
    assert (a.len == 1)
    o = a.origin
    assert (o.type == ORIGIN_IGP)
    a = b3.update.attributes[5]
    assert (a.optional)
    assert (not a.transitive)
    assert (not a.partial)
    assert (a.extended_length)
    assert (a.type == MP_REACH_NLRI)
    assert (a.len == 30)
    m = a.mp_reach_nlri
    assert (m.afi == AFI_IPV4)
    assert (len(m.snpas) == 0)
    assert (len(m.announced) == 1)
    p = m.announced[0]
    assert (p.len == 96)

    b4 = BGP(__bgp4)
    assert (b4.len == 45)
    assert (b4.type == OPEN)
    assert (b4.open.asn == 237)
    assert (b4.open.param_len == 16)
    assert (len(b4.open.parameters) == 3)
    p = b4.open.parameters[0]
    assert (p.type == CAPABILITY)
    assert (p.len == 6)
    c = p.capability
    assert (c.code == CAP_MULTIPROTOCOL)
    assert (c.len == 4)
    assert (c.data == b'\x00\x01\x00\x01')
    c = b4.open.parameters[2].capability
    assert (c.code == CAP_ROUTE_REFRESH)
    assert (c.len == 0)

    b5 = BGP(__bgp5)
    assert (b5.len == 96)
    assert (b5.type == UPDATE)
    assert (len(b5.update.withdrawn) == 0)
    a = b5.update.attributes[-1]
    assert (a.type == MP_REACH_NLRI)
    assert (a.len == 36)
    m = a.mp_reach_nlri
    assert (m.afi == AFI_L2VPN)
    assert (m.safi == SAFI_EVPN)
    r = m.announced[0]
    assert (r.type == 1)
    assert (r.len == 25)
    assert (r.rd == b'\x00\x01\x01\x01\x01\x02\x00\x02')
    assert (r.esi == b'\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00')
    assert (r.eth_id == b'\x00\x00\x00\x02')
    assert (r.mpls_label_stack == b'\x00\x00\x02')

    b6 = BGP(__bgp6)
    assert (b6.len == 111)
    assert (b6.type == UPDATE)
    assert (len(b6.update.withdrawn) == 0)
    a = b6.update.attributes[-1]
    assert (a.type == MP_REACH_NLRI)
    assert (a.len == 51)
    m = a.mp_reach_nlri
    assert (m.afi == AFI_L2VPN)
    assert (m.safi == SAFI_EVPN)
    r = m.announced[0]
    assert (r.type == 2)
    assert (r.len == 40)
    assert (r.rd == b'\x00\x01\x01\x01\x01\x02\x00\x02')
    assert (r.esi == b'\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00')
    assert (r.eth_id == b'\x00\x00\x00\x02')
    assert (r.mac_address_length == 48)
    assert (r.mac_address == b'\xcc\xaa\x02\x9c\xd8\x29')
    assert (r.ip_address_length == 32)
    assert (r.ip_address == b'\xc0\xb4\x01\x02')
    assert (r.mpls_label_stack == b'\x00\x00\x02\x00\x00\x00')

    b7 = BGP(__bgp7)
    assert (b7.len == 88)
    assert (b7.type == UPDATE)
    assert (len(b7.update.withdrawn) == 0)
    a = b7.update.attributes[-1]
    assert (a.type == MP_REACH_NLRI)
    assert (a.len == 28)
    m = a.mp_reach_nlri
    assert (m.afi == AFI_L2VPN)
    assert (m.safi == SAFI_EVPN)
    r = m.announced[0]
    assert (r.type == 3)
    assert (r.len == 17)
    assert (r.rd == b'\x00\x01\x01\x01\x01\x02\x00\x02')
    assert (r.eth_id == b'\x00\x00\x00\x02')
    assert (r.ip_address_length == 32)
    assert (r.ip_address == b'\xc0\xb4\x01\x02')

    b8 = BGP(__bgp8)
    assert (b8.len == 95)
    assert (b8.type == UPDATE)
    assert (len(b8.update.withdrawn) == 0)
    a = b8.update.attributes[-1]
    assert (a.type == MP_REACH_NLRI)
    assert (a.len == 35)
    m = a.mp_reach_nlri
    assert (m.afi == AFI_L2VPN)
    assert (m.safi == SAFI_EVPN)
    r = m.announced[0]
    assert (r.type == 4)
    assert (r.len == 24)
    assert (r.rd == b'\x00\x01\x01\x01\x01\x02\x00\x02')
    assert (r.esi == b'\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00')
    assert (r.ip_address_length == 32)
    assert (r.ip_address == b'\xc0\xb4\x01\x02')

    b9 = BGP(__bgp9)
    assert (b9.len == 123)
    assert (b9.type == UPDATE)
    assert (len(b9.update.withdrawn) == 0)
    a = b9.update.attributes[-1]
    assert (a.type == MP_REACH_NLRI)
    assert (a.len == 63)
    m = a.mp_reach_nlri
    assert (m.afi == AFI_L2VPN)
    assert (m.safi == SAFI_EVPN)
    r = m.announced[0]
    assert (r.type == 2)
    assert (r.len == 52)
    assert (r.rd == b'\x00\x01\x01\x01\x01\x02\x00\x02')
    assert (r.esi == b'\x05\x00\x00\x03\xe8\x00\x00\x04\x00\x00')
    assert (r.eth_id == b'\x00\x00\x00\x02')
    assert (r.mac_address_length == 48)
    assert (r.mac_address == b'\xcc\xaa\x02\x9c\xd8\x29')
    assert (r.ip_address_length == 128)
    assert (r.ip_address == b'\xc0\xb4\x01\x02\xc0\xb4\x01\x02\xc0\xb4\x01\x02\xc0\xb4\x01\x02')
    assert (r.mpls_label_stack == b'\x00\x00\x02\x00\x00\x00')


def test_bgp_mp_nlri_20_1_mp_reach_nlri_next_hop():
    # test for https://github.com/kbandla/dpkt/issues/485
    __bgp = (
        b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x6c\x02\x00\x00\x00\x55\x40\x01'
        b'\x01\x00\x40\x02\x04\x02\x01\xfd\xe9\x80\x04\x04\x00\x00\x00\x00\x80\x0e\x40\x00\x02\x01\x20\x20\x01'
        b'\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfe\x80\x00\x00\x00\x00\x00\x00\xc0\x01\x0b'
        b'\xff\xfe\x7e\x00\x00\x00\x40\x20\x01\x0d\xb8\x00\x01\x00\x02\x40\x20\x01\x0d\xb8\x00\x01\x00\x01\x40'
        b'\x20\x01\x0d\xb8\x00\x01\x00\x00'
    )
    assert (__bgp == bytes(BGP(__bgp)))
    bgp = BGP(__bgp)
    assert (len(bgp.data) == 89)
    assert (bgp.type == UPDATE)
    assert (len(bgp.update.withdrawn) == 0)
    assert (len(bgp.update.announced) == 0)
    assert (len(bgp.update.attributes) == 4)

    attribute = bgp.update.attributes[0]
    assert (attribute.type == ORIGIN)
    assert (not attribute.optional)
    assert (attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.len == 1)
    o = attribute.origin
    assert (o.type == ORIGIN_IGP)

    attribute = bgp.update.attributes[1]
    assert (attribute.type == AS_PATH)
    assert (not attribute.optional)
    assert (attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 64)
    assert (attribute.len == 4)
    assert (len(attribute.as_path.segments) == 1)
    segment = attribute.as_path.segments[0]
    assert (segment.type == AS_SEQUENCE)
    assert (segment.len == 1)
    assert (len(segment.path) == 1)
    assert (segment.path[0] == 65001)

    attribute = bgp.update.attributes[2]
    assert (attribute.type == MULTI_EXIT_DISC)
    assert (attribute.optional)
    assert (not attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x80)
    assert (attribute.len == 4)
    assert (attribute.multi_exit_disc.value == 0)

    attribute = bgp.update.attributes[3]
    assert (attribute.type == MP_REACH_NLRI)
    assert (attribute.optional)
    assert (not attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x80)
    assert (attribute.len == 64)
    mp_reach_nlri = attribute.mp_reach_nlri
    assert (mp_reach_nlri.afi == AFI_IPV6)
    assert (mp_reach_nlri.safi == SAFI_UNICAST)
    assert (len(mp_reach_nlri.snpas) == 0)
    assert (len(mp_reach_nlri.announced) == 3)
    prefix = mp_reach_nlri.announced[0]
    assert (socket.inet_ntop(socket.AF_INET6, prefix.prefix) == '2001:db8:1:2::')
    assert (prefix.len == 64)
    prefix = mp_reach_nlri.announced[1]
    assert (socket.inet_ntop(socket.AF_INET6, prefix.prefix) == '2001:db8:1:1::')
    assert (prefix.len == 64)
    prefix = mp_reach_nlri.announced[2]
    assert (socket.inet_ntop(socket.AF_INET6, prefix.prefix) == '2001:db8:1::')
    assert (prefix.len == 64)
    assert (len(mp_reach_nlri.next_hops) == 2)
    assert (socket.inet_ntop(socket.AF_INET6, mp_reach_nlri.next_hops[0]) == '2001:db8::1')
    assert (socket.inet_ntop(socket.AF_INET6, mp_reach_nlri.next_hops[1]) == 'fe80::c001:bff:fe7e:0')
    assert (mp_reach_nlri.next_hop == b''.join(mp_reach_nlri.next_hops))


def test_bgp_add_path_6_1_as_path():
    # test for https://github.com/kbandla/dpkt/issues/481
    # Error processing BGP data: packet 6 : message 1 of bgp-add-path.cap
    # https://packetlife.net/media/captures/bgp-add-path.cap
    __bgp = (
        b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x59\x02\x00\x00\x00\x30\x40\x01'
        b'\x01\x00\x40\x02\x06\x02\x01\x00\x00\xfb\xff\x40\x03\x04\x0a\x00\x0e\x01\x80\x04\x04\x00\x00\x00\x00'
        b'\x40\x05\x04\x00\x00\x00\x64\x80\x0a\x04\x0a\x00\x22\x04\x80\x09\x04\x0a\x00\x0f\x01\x00\x00\x00\x01'
        b'\x20\x05\x05\x05\x05\x00\x00\x00\x01\x20\xc0\xa8\x01\x05'
    )
    bgp = BGP(__bgp)
    assert (__bgp == bytes(bgp))
    assert (len(bgp) == 89)
    assert (bgp.type == UPDATE)
    assert (len(bgp.update.withdrawn) == 0)
    announced = bgp.update.announced
    assert (len(announced) == 2)
    assert (announced[0].len == 32)
    assert (announced[0].path_id == 1)
    assert (socket.inet_ntop(socket.AF_INET, bytes(announced[0].prefix)) == '5.5.5.5')
    assert (announced[1].len == 32)
    assert (announced[1].path_id == 1)
    assert (socket.inet_ntop(socket.AF_INET, bytes(announced[1].prefix)) == '192.168.1.5')

    assert (len(bgp.update.attributes) == 7)

    attribute = bgp.update.attributes[0]
    assert (attribute.type == ORIGIN)
    assert (not attribute.optional)
    assert (attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x40)
    assert (attribute.len == 1)
    assert (attribute.origin.type == ORIGIN_IGP)

    attribute = bgp.update.attributes[1]
    assert (attribute.type == AS_PATH)
    assert (not attribute.optional)
    assert (attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x40)
    assert (attribute.len == 6)
    assert (len(attribute.as_path.segments) == 1)
    segment = attribute.as_path.segments[0]
    assert (segment.type == AS_SEQUENCE)
    assert (segment.len == 1)
    assert (len(segment.path) == 1)
    assert (segment.path[0] == 64511)

    attribute = bgp.update.attributes[2]
    assert (attribute.type == NEXT_HOP)
    assert (not attribute.optional)
    assert (attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x40)
    assert (attribute.len == 4)
    assert (socket.inet_ntop(socket.AF_INET, bytes(attribute.next_hop)) == '10.0.14.1')

    attribute = bgp.update.attributes[3]
    assert (attribute.type == MULTI_EXIT_DISC)
    assert (attribute.optional)
    assert (not attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x80)
    assert (attribute.len == 4)
    assert (attribute.multi_exit_disc.value == 0)

    attribute = bgp.update.attributes[4]
    assert (attribute.type == LOCAL_PREF)
    assert (not attribute.optional)
    assert (attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x40)
    assert (attribute.len == 4)
    assert (attribute.local_pref.value == 100)

    attribute = bgp.update.attributes[5]
    assert (attribute.type == CLUSTER_LIST)
    assert (attribute.optional)
    assert (not attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x80)
    assert (attribute.len == 4)
    assert (socket.inet_ntop(socket.AF_INET, bytes(attribute.cluster_list)) == '10.0.34.4')

    attribute = bgp.update.attributes[6]
    assert (attribute.type == ORIGINATOR_ID)
    assert (attribute.optional)
    assert (not attribute.transitive)
    assert (not attribute.partial)
    assert (not attribute.extended_length)
    assert (attribute.flags == 0x80)
    assert (attribute.len == 4)
    assert (socket.inet_ntop(socket.AF_INET, bytes(attribute.originator_id)) == '10.0.15.1')


def test_attribute_accessors():
    from binascii import unhexlify

    buf = unhexlify(
        '00'  # flags
        '01'  # type (ORIGIN)

        '01'  # length
        '00'  # Origin type
    )
    attribute = BGP.Update.Attribute(buf)
    assert isinstance(attribute.data, BGP.Update.Attribute.Origin)
    for attr in ['optional', 'transitive', 'partial', 'extended_length']:
        assert getattr(attribute, attr) == 0

        # check we can set..
        setattr(attribute, attr, 1)
        assert getattr(attribute, attr) == 1

        # and also unset
        setattr(attribute, attr, 0)
        assert getattr(attribute, attr) == 0


def test_snpa():
    from binascii import unhexlify

    buf = unhexlify(
        '04'    # len (in semi-octets)
        '1234'  # data
    )
    snpa = BGP.Update.Attribute.MPReachNLRI.SNPA(buf)
    assert snpa.len == 4  # length of the data in semi-octets
    assert len(snpa) == 3  # length of the snpa in bytes (including header)
    assert bytes(snpa) == buf


def test_mpreachnlri():
    from binascii import unhexlify

    buf = unhexlify(
        '0000'  # afi
        '00'    # safi

        '00'    # nlen
        '01'    # num SNPAs

        # SNPA
        '04'    # len
        '1234'  # data
    )
    mp = BGP.Update.Attribute.MPReachNLRI(buf)
    assert len(mp.snpas) == 1
    assert bytes(mp) == buf


def test_notification():
    from binascii import unhexlify

    buf_notification = unhexlify(
        '11'   # code
        '22'   # subcode

        '33'   # error
    )
    notification = BGP.Notification(buf_notification)
    assert notification.code == 0x11
    assert notification.subcode == 0x22
    assert notification.error == b'\x33'
    assert bytes(notification) == buf_notification

    buf_bgp_hdr = unhexlify(
        '11111111111111111111111111111111'  # marker
        '0016'  # len
        '03'    # type (NOTIFICATION)
    )
    bgp = BGP(buf_bgp_hdr + buf_notification)

    assert hasattr(bgp, 'notification')
    assert isinstance(bgp.data, BGP.Notification)
    assert bgp.data.code == 0x11
    assert bgp.data.subcode == 0x22
    assert bgp.data.error == b'\x33'
    assert bytes(bgp) == buf_bgp_hdr + buf_notification


def test_keepalive():
    keepalive = BGP.Keepalive(b'\x11')
    assert len(keepalive) == 0
    assert bytes(keepalive) == b''


def test_routegeneric():
    from binascii import unhexlify

    buf = unhexlify(
        '08'  # len (bits)
        '11'  # prefix
    )
    routegeneric = RouteGeneric(buf)
    assert routegeneric.len == 8
    assert routegeneric.prefix == b'\x11'

    assert bytes(routegeneric) == buf
    assert len(routegeneric) == 2


def test_routeipv4():
    from binascii import unhexlify

    buf = unhexlify(
        '08'  # len (bits)

        '11'  # prefix
    )
    routeipv4 = RouteIPV4(buf)
    assert routeipv4.len == 8  # prefix len in bits
    assert routeipv4.prefix == b'\x11\x00\x00\x00'

    assert repr(routeipv4) == "RouteIPV4(17.0.0.0/8)"
    assert bytes(routeipv4) == buf
    assert len(routeipv4) == 2  # header + prefix(bytes)


def test_routeipv6():
    from binascii import unhexlify

    buf = unhexlify(
        '08'  # len (bits)
        '22'  # prefix
    )

    routeipv6 = RouteIPV4(buf)
    assert routeipv6.len == 8  # prefix len in bits
    assert routeipv6.prefix == b'\x22\x00\x00\x00'

    assert bytes(routeipv6) == buf
    assert len(routeipv6) == 2  # header + prefix(bytes)


def test_extendedrouteipv4():
    from binascii import unhexlify

    buf = unhexlify(
        '00000001'  # path_id
        '20'        # len (bits)
        '05050505'  # prefix
    )
    extendedrouteipv4 = ExtendedRouteIPV4(buf)
    assert extendedrouteipv4.path_id == 1
    assert extendedrouteipv4.len == 32
    assert extendedrouteipv4.prefix == unhexlify('05050505')
    assert repr(extendedrouteipv4) == "ExtendedRouteIPV4(5.5.5.5/32 PathId 1)"

    assert bytes(extendedrouteipv4) == buf
    assert len(extendedrouteipv4) == len(buf)


def test_routeevpn():
    from binascii import unhexlify

    buf = unhexlify(
        '02'  # type
        '1a'  # len

        # route distinguisher
        '1111111111111111'

        # esi
        '22222222222222222222'

        # eth_id
        '33333333'

        # mac address
        '00'  # len (bits)

        # ip address
        '00'  # len (bits)

        # mpls
        '6666'  # label stack
    )

    routeevpn = RouteEVPN(buf)
    assert routeevpn.type == 2
    assert routeevpn.len == 26

    assert routeevpn.esi == unhexlify('22222222222222222222')
    assert routeevpn.eth_id == unhexlify('33333333')

    assert routeevpn.mac_address_length == 0
    assert routeevpn.mac_address is None

    assert routeevpn.ip_address_length == 0
    assert routeevpn.ip_address is None

    assert routeevpn.mpls_label_stack == unhexlify('6666')

    assert bytes(routeevpn) == buf
    assert len(routeevpn) == len(buf)


def test_route_refresh():
    from binascii import unhexlify
    buf_route_refresh = unhexlify(
        '1111'  # afi
        '22'    # rsvd
        '33'    # safi
    )
    route_refresh = BGP.RouteRefresh(buf_route_refresh)
    assert route_refresh.afi == 0x1111
    assert route_refresh.rsvd == 0x22
    assert route_refresh.safi == 0x33
    assert bytes(route_refresh) == buf_route_refresh

    buf_bgp_hdr = unhexlify(
        '11111111111111111111111111111111'  # marker
        '0017'  # len
        '05'    # type (ROUTE_REFRESH)
    )
    bgp = BGP(buf_bgp_hdr + buf_route_refresh)

    assert hasattr(bgp, 'route_refresh')
    assert isinstance(bgp.data, BGP.RouteRefresh)
    assert bgp.data.afi == 0x1111
    assert bgp.data.rsvd == 0x22
    assert bgp.data.safi == 0x33
    assert bytes(bgp) == buf_bgp_hdr + buf_route_refresh


def test_mpunreachnlri():
    from binascii import unhexlify
    buf_routeipv4 = unhexlify(
        '08'  # len (bits)
        '11'  # prefix
    )

    buf_routeipv6 = unhexlify(
        '08'  # len (bits)
        '22'  # prefix
    )

    buf_routeevpn = unhexlify(
        '02'  # type
        '1a'  # len

        # route distinguisher
        '1111111111111111'

        # esi
        '22222222222222222222'

        # eth_id
        '33333333'

        # mac address
        '00'  # len (bits)

        # ip address
        '00'  # len (bits)

        # mpls
        '6666'  # label stack
    )

    buf_routegeneric = unhexlify(
        '08'  # len (bits)
        '33'  # prefix
    )

    afi = struct.Struct('>H')
    routes = (
        (AFI_IPV4, buf_routeipv4, RouteIPV4),
        (AFI_IPV6, buf_routeipv6, RouteIPV6),
        (AFI_L2VPN, buf_routeevpn, RouteEVPN),
        # this afi does not exist, so we will parse as RouteGeneric
        (1234, buf_routegeneric, RouteGeneric),
    )

    for afi_id, buf, cls in routes:
        buf = afi.pack(afi_id) + b'\xcc' + buf
        mpu = BGP.Update.Attribute.MPUnreachNLRI(buf)

        assert mpu.afi == afi_id
        assert mpu.safi == 0xcc
        assert len(mpu.data) == 1
        route = mpu.data[0]
        assert isinstance(route, cls)

        assert bytes(mpu) == buf
        assert len(mpu) == len(buf)

    # test the unpacking of the routes, as an Attribute
    attribute_hdr = struct.Struct('BBB')
    for afi_id, buf, cls in routes:
        buf_mpunreachnlri = afi.pack(afi_id) + b'\xcc' + buf
        buf_attribute_hdr = attribute_hdr.pack(0, MP_UNREACH_NLRI, len(buf_mpunreachnlri))
        buf = buf_attribute_hdr + buf_mpunreachnlri

        attribute = BGP.Update.Attribute(buf)
        assert isinstance(attribute.data, BGP.Update.Attribute.MPUnreachNLRI)
        routes = attribute.data.data
        assert len(routes) == 1
        assert isinstance(routes[0], cls)


def test_update_withdrawn():
    from binascii import unhexlify
    buf_ipv4 = unhexlify(
        '08'  # len (bits)
        '11'  # prefix
    )
    packed_length = struct.Struct('>H').pack
    wlen, plen = packed_length(len(buf_ipv4)), packed_length(0)

    buf = wlen + buf_ipv4 + plen
    update = BGP.Update(buf)

    assert len(update.withdrawn) == 1
    route = update.withdrawn[0]
    assert isinstance(route, RouteIPV4)
    assert bytes(update) == buf


def test_bgp_duplicate_origin_is_rejected():
    import pytest

    attrs = (
        bytes([0x40, ORIGIN, 1, ORIGIN_IGP]) +
        bytes([0x40, ORIGIN, 1, ORIGIN_EGP])
    )
    update = struct.pack('>HH', 0, len(attrs)) + attrs
    packet = b'\xff' * 16 + struct.pack(
        '>HB', 19 + len(update), UPDATE) + update

    with pytest.raises(dpkt.UnpackError):
        BGP(packet)


def test_bgp_invalid_attribute_length_is_rejected():
    import pytest

    # ORIGIN is always exactly one byte on the wire.
    attrs = bytes([0x40, ORIGIN, 2, ORIGIN_IGP, 0])
    update = struct.pack('>HH', 0, len(attrs)) + attrs
    packet = b'\xff' * 16 + struct.pack(
        '>HB', 19 + len(update), UPDATE) + update

    with pytest.raises(dpkt.UnpackError):
        BGP(packet)


def test_bgp_truncated_mp_reach_prefix_is_rejected():
    import pytest

    next_hop = b'\x20\x01\x0d\xb8' + b'\x00' * 12
    mp_reach = (
        struct.pack('>HBB', AFI_IPV6, SAFI_UNICAST, len(next_hop)) +
        next_hop +
        b'\x00' +                  # reserved / zero SNPAs
        bytes([64, 0x20, 0x01])    # /64 but only two prefix bytes
    )
    attrs = bytes([0x80, MP_REACH_NLRI, len(mp_reach)]) + mp_reach
    update = struct.pack('>HH', 0, len(attrs)) + attrs
    packet = b'\xff' * 16 + struct.pack(
        '>HB', 19 + len(update), UPDATE) + update

    with pytest.raises(dpkt.UnpackError):
        BGP(packet)


def test_bgp_failed_reunpack_keeps_previous_generation():
    import pytest

    origin = bytes([0x40, ORIGIN, 1, ORIGIN_IGP])
    nlri = bytes([24, 192, 168, 1])
    update = struct.pack('>HH', 0, len(origin)) + origin + nlri
    packet = b'\xff' * 16 + struct.pack(
        '>HB', 19 + len(update), UPDATE) + update
    bgp = BGP(packet)
    old_update = bgp.update
    old_attributes = bgp.update.attributes
    old_announced = bgp.update.announced

    bad_attrs = origin + bytes([0x40, ORIGIN, 1, INCOMPLETE])
    bad_update = struct.pack('>HH', 0, len(bad_attrs)) + bad_attrs
    bad_packet = b'\xff' * 16 + struct.pack(
        '>HB', 19 + len(bad_update), UPDATE) + bad_update

    with pytest.raises(dpkt.UnpackError):
        bgp.unpack(bad_packet)

    assert bgp.update is old_update
    assert bgp.update.attributes is old_attributes
    assert bgp.update.announced is old_announced
    assert bgp.update.announced[0].prefix == b'\xc0\xa8\x01\x00'


def test_parameters():
    from binascii import unhexlify
    buf = unhexlify(
        '44'        # v
        '1111'      # asn
        '2222'      # holdtime
        '33333333'  # identifier
        '03'        # param_len

        # Parameter
        '01'  # type (AUTHENTICATION)
        '01'  # len

        # Authentication
        '11'  # code
    )
    bgp_open = BGP.Open(buf)
    assert len(bgp_open.parameters) == 1
    parameter = bgp_open.parameters[0]

    assert isinstance(parameter, BGP.Open.Parameter)
    assert isinstance(parameter.data, BGP.Open.Parameter.Authentication)

    assert bytes(bgp_open) == buf
    assert len(bgp_open) == len(buf)


def test_reservedcommunities():
    from binascii import unhexlify
    buf = unhexlify(
        # ReservedCommunity
        '00002222'  # value
    )
    communities = BGP.Update.Attribute.Communities(buf)
    assert len(communities.data) == 1

    community = communities.data[0]
    assert isinstance(community, BGP.Update.Attribute.Communities.ReservedCommunity)
    assert len(community) == 4
    assert bytes(community) == buf

    assert len(communities) == 4
    assert bytes(communities) == buf
