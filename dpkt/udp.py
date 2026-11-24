# $Id: udp.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""User Datagram Protocol."""
from __future__ import absolute_import

from . import dpkt

UDP_HDR_LEN = 8
UDP_PORT_MAX = 65535


class UDP(dpkt.Packet):
    """User Datagram Protocol.

    User Datagram Protocol (UDP) is one of the core members of the Internet protocol suite.
    With UDP, computer applications can send messages, in this case referred to as datagrams,
    to other hosts on an Internet Protocol (IP) network. Prior communications are not required
    in order to set up communication channels or data paths.

    Attributes:
        __hdr__: Header fields of UDP.
            sport: (int): Source port. (2 bytes)
            dport: (int): Destination port. (2 bytes)
            ulen: (int): Length. (2 bytes)
            sum: (int): Checksum. (2 bytes)
    """

    __hdr__ = (
        ('sport', 'H', 0xdead),
        ('dport', 'H', 0),
        ('ulen', 'H', 8),
        ('sum', 'H', 0)
    )

    def __init__(self, *args, **kwargs):
        self._truncated = False
        self._ip_src = None
        self._ip_dst = None
        self._ip_version = None
        super(UDP, self).__init__(*args, **kwargs)

    @property
    def truncated(self):
        """True when the UDP payload is shorter than the length field claims."""
        return self._truncated

    @truncated.setter
    def truncated(self, value):
        self._truncated = bool(value)

    @property
    def is_truncated(self):
        return self.truncated

    def unpack(self, buf):
        self._truncated = False
        self._ip_src = None
        self._ip_dst = None
        self._ip_version = None
        dpkt.Packet.unpack(self, buf)

        # A UDP length of zero is only meaningful for IPv6 jumbograms, where
        # the enclosing IP layer provides the real payload length.
        if self.ulen == 0:
            self._truncated = False
            self._wire_len = len(buf)
            return

        if self.ulen < UDP_HDR_LEN:
            raise dpkt.UnpackError('invalid UDP length %d' % self.ulen)

        captured_len = len(buf)
        if captured_len < self.ulen:
            # This is the pcap snaplen case: keep the captured bytes so an IDS
            # can inspect the packet, but remember that the datagram is not
            # complete.  Checksum verification must not claim it is valid.
            self._truncated = True
            self._wire_len = self.ulen
            self._captured_len = captured_len
            return

        if captured_len > self.ulen:
            # Bytes beyond the declared UDP length are not part of this
            # datagram.  Accepting them would let an attacker hide trailing
            # data from length-based consumers while checksum code sees it.
            raise dpkt.UnpackError(
                'UDP length %d does not match buffer length %d'
                % (self.ulen, captured_len))

        self._truncated = False
        self._wire_len = self.ulen
        self._captured_len = captured_len

    def verify_checksum(self, src=None, dst=None):
        """Verify the UDP checksum.

        Returns True/False for a complete datagram, and None when a reliable
        conclusion cannot be reached (truncated input, missing pseudoheader
        information, or a zero checksum that means checksumming was disabled).
        """
        if self.truncated:
            return None

        if src is None:
            src = self._ip_src
        if dst is None:
            dst = self._ip_dst

        if self.sum == 0:
            # RFC 768: an all-zero transmitted checksum means the sender did
            # not generate one.  For IPv4 this is a valid, common path; for
            # IPv6 the checksum is mandatory, so a zero value is not clean.
            if self._ip_version == 6:
                return False
            return True

        if src is None or dst is None:
            return None

        p = bytes(self)
        pseudo = dpkt.struct.pack(
            '>4s4sxBH', src, dst, 17, len(p))
        s = dpkt.in_cksum_add(0, pseudo)
        s = dpkt.in_cksum_add(s, p)
        return dpkt.in_cksum_done(s) == 0

    @property
    def checksum_valid(self):
        return self.verify_checksum()


def test_udp_length_mismatch():
    import pytest

    with pytest.raises(dpkt.UnpackError):
        UDP(b'\x00\x35\x00\x36\x00\x0a\x00\x00abc')


def test_udp_truncation_blocks_clean_checksum():
    udp = UDP(b'\x00\x35\x00\x36\x00\x0a\x12\x34a')
    assert udp.truncated
    assert udp.is_truncated
    assert udp.verify_checksum() is None
    assert udp.checksum_valid is None


def test_udp_zero_checksum_is_accepted():
    udp = UDP(b'\x00\x35\x00\x36\x00\x0a\x00\x00ab')
    assert not udp.truncated
    assert udp.verify_checksum() is True
