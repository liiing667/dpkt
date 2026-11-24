# $Id: asn1.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Abstract Syntax Notation #1."""
from __future__ import absolute_import
from __future__ import print_function

import struct
from calendar import timegm

from . import dpkt
from .compat import compat_ord

# Type class
CLASSMASK = 0xc0
UNIVERSAL = 0x00
APPLICATION = 0x40
CONTEXT = 0x80
PRIVATE = 0xc0

# Constructed (vs. primitive)
CONSTRUCTED = 0x20

# Universal-class tags
TAGMASK = 0x1f
INTEGER = 2
BIT_STRING = 3  # arbitrary bit string
OCTET_STRING = 4  # arbitrary octet string
NULL = 5
OID = 6  # object identifier
SEQUENCE = 16  # ordered collection of types
SET = 17  # unordered collection of types
PRINT_STRING = 19  # printable string
T61_STRING = 20  # T.61 (8-bit) character string
IA5_STRING = 22  # ASCII
UTC_TIME = 23

# Maximum nesting depth the decoder will descend into.  Real-world DER
# certificates are only a handful of levels deep; capping this keeps the
# recursive decoder from exhausting the C stack on adversarial input before a
# scanner is able to reach a verdict.
MAX_DEPTH = 200

# End-of-contents marker used by BER indefinite-length encodings (forbidden
# in DER, but still parsed defensively).
_EOC = b'\x00\x00'


def utctime(buf):
    """Convert ASN.1 UTCTime string to UTC float.

    TODO: Long description here.

    Args:
        buf: A buffer with format "yymnddhhmm"

    Returns:
        A floating point number, indicates seconds since the Epoch.
    """
    yy = int(buf[:2])
    mn = int(buf[2:4])
    dd = int(buf[4:6])
    hh = int(buf[6:8])
    mm = int(buf[8:10])
    try:
        ss = int(buf[10:12])
        buf = buf[12:]
    except TypeError:
        ss = 0
        buf = buf[10:]

    if buf[0] == '+':
        hh -= int(buf[1:3])
        mm -= int(buf[3:5])
    elif buf[0] == '-':
        hh += int(buf[1:3])
        mm += int(buf[3:5])
    return timegm((2000 + yy, mn, dd, hh, mm, ss, 0, 0, 0))


def decode(buf):
    """Sleazy, bounded ASN.1 decoder.

    TODO: Long description here.

    Args:
        buf: A buffer with Sleazy ASN.1 data.

    Returns:
        A list of (id, value) tuples from ASN.1 BER/DER encoded buffer.

    Raises:
        UnpackError: The buffer is truncated, declares a length that exceeds
            its remaining bytes, nests more than ``MAX_DEPTH`` levels deep, or
            is otherwise malformed.  Decoding always fails closed instead of
            raising ``IndexError``, ``struct.error`` or ``RecursionError``.
    """
    msg, _ = _decode(buf, 0, len(buf), 0, False)
    return msg


def _decode(buf, start, end, depth, window_indefinite):
    """Decode one TLV window, sharing one byte/depth budget across recursion.

    The window is the shared range ``buf[start:end]``, so every recursive
    descent is bounded by the same buffer instead of trusting a freshly
    re-derived length.  Returns ``(msg, next_off)``; when
    ``window_indefinite`` is true parsing stops at the end-of-contents octets
    (0x00 0x00) and ``next_off`` points at them.
    """
    if depth > MAX_DEPTH:
        raise dpkt.UnpackError(
            'excessive ASN.1 nesting depth > %d' % MAX_DEPTH)
    msg = []
    off = start
    while off < end:
        if window_indefinite and buf[off:off + 2] == _EOC:
            return msg, off
        # Truncated type/length header.
        if end - off < 2:
            raise dpkt.UnpackError('truncated ASN.1 header')
        t = compat_ord(buf[off])
        constructed = t & CONSTRUCTED
        tag = t & TAGMASK
        l_ = compat_ord(buf[off + 1])
        off += 2

        tlv_indefinite = False
        if l_ == 128:
            # Indefinite length is only legal for constructed BER encodings.
            if not constructed:
                raise dpkt.UnpackError(
                    'indefinite length on primitive ASN.1 tag %d' % t)
            tlv_indefinite = True
            c = 0
        elif l_ > 128:
            c = l_ & 127
            if c == 1:
                if end - off < 1:
                    raise dpkt.UnpackError('truncated ASN.1 long-form length')
                l_ = compat_ord(buf[off])
            elif c == 2:
                if end - off < 2:
                    raise dpkt.UnpackError('truncated ASN.1 long-form length')
                l_ = struct.unpack('>H', buf[off:off + 2])[0]
            elif c == 3:
                if end - off < 3:
                    raise dpkt.UnpackError('truncated ASN.1 long-form length')
                l_ = struct.unpack('>I', b'\x00' + buf[off:off + 3])[0]
            elif c == 4:
                if end - off < 4:
                    raise dpkt.UnpackError('truncated ASN.1 long-form length')
                l_ = struct.unpack('>I', buf[off:off + 4])[0]
            else:
                # XXX - can be up to 127 bytes, but...
                raise dpkt.UnpackError(
                    'excessive long-form ASN.1 length %d' % l_)
        else:
            c = 0

        # Skip the length octets.
        off += c

        if tlv_indefinite:
            # Parse until this TLV's end-of-contents octets (0x00 0x00).
            value, eoc_at = _decode(buf, off, end, depth + 1, True)
            if eoc_at + 2 > end or buf[eoc_at:eoc_at + 2] != _EOC:
                raise dpkt.UnpackError(
                    'missing end-of-contents for indefinite-length ASN.1 tag')
            off = eoc_at + len(_EOC)
            msg.append((t, value))
            continue

        # Definite length: the declared content must fit inside the shared
        # window budget rather than being trusted on its own.
        if l_ > end - off:
            raise dpkt.UnpackError(
                'ASN.1 content length %d exceeds %d remaining bytes'
                % (l_, end - off))
        content_end = off + l_

        # Parse content.
        if constructed:
            value, inner_end = _decode(
                buf, off, content_end, depth + 1, False)
            if inner_end != content_end:
                raise dpkt.UnpackError(
                    'trailing %d bytes in constructed ASN.1 tag %d'
                    % (content_end - inner_end, t))
            msg.append((t, value))
        elif tag == INTEGER:
            content = buf[off:content_end]
            # Arbitrary-length two's-complement big-endian integer (RSA
            # moduli and signatures are hundreds of bytes).  The length was
            # already bounded against the shared window above, so this cannot
            # run away.
            n_ = 0
            for octet in content:
                n_ = (n_ << 8) | compat_ord(octet)
            msg.append((t, n_))
        elif tag == UTC_TIME:
            content = buf[off:content_end]
            try:
                msg.append((t, utctime(content)))
            except (ValueError, IndexError, TypeError) as e:
                raise dpkt.UnpackError('invalid ASN.1 UTCTime: %s' % e)
        else:
            msg.append((t, buf[off:content_end]))

        # Skip content.
        off = content_end
    return msg, off


def test_asn1():
    s = (
        b'0\x82\x02Q\x02\x01\x0bc\x82\x02J\x04xcn=Douglas J Song 1, ou=Information Technology Division,'
        b' ou=Faculty and Staff, ou=People, o=University of Michigan, c=US\n\x01\x00\n\x01\x03\x02\x01'
        b'\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectclass0\x82\x01\xb0\x04\rmemberOfGroup\x04\x03acl'
        b'\x04\x02cn\x04\x05title\x04\rpostalAddress\x04\x0ftelephoneNumber\x04\x04mail\x04\x06member'
        b'\x04\thomePhone\x04\x11homePostalAddress\x04\x0bobjectClass\x04\x0bdescription\x04\x18'
        b'facsimileTelephoneNumber\x04\x05pager\x04\x03uid\x04\x0cuserPassword\x04\x08joinable\x04\x10'
        b'associatedDomain\x04\x05owner\x04\x0erfc822ErrorsTo\x04\x08ErrorsTo\x04\x10rfc822RequestsTo\x04\n'
        b'RequestsTo\x04\tmoderator\x04\nlabeledURL\x04\nonVacation\x04\x0fvacationMessage\x04\x05drink\x04\x0e'
        b'lastModifiedBy\x04\x10lastModifiedTime\x04\rmodifiersname\x04\x0fmodifytimestamp\x04\x0ccreatorsname'
        b'\x04\x0fcreatetimestamp'
    )
    assert decode(s) == [
        (48, [
            (2, 11),
            (99, [
                (4, (
                    b'cn=Douglas J Song 1, '
                    b'ou=Information Technology Division, '
                    b'ou=Faculty and Staff, '
                    b'ou=People, '
                    b'o=University of Michigan, '
                    b'c=US'
                )),
                (10, b'\x00'),
                (10, b'\x03'),
                (2, 0),
                (2, 0),
                (1, b'\x00'),
                (135, b'objectclass'),
                (48, [
                    (4, b'memberOfGroup'),
                    (4, b'acl'),
                    (4, b'cn'),
                    (4, b'title'),
                    (4, b'postalAddress'),
                    (4, b'telephoneNumber'),
                    (4, b'mail'),
                    (4, b'member'),
                    (4, b'homePhone'),
                    (4, b'homePostalAddress'),
                    (4, b'objectClass'),
                    (4, b'description'),
                    (4, b'facsimileTelephoneNumber'),
                    (4, b'pager'),
                    (4, b'uid'),
                    (4, b'userPassword'),
                    (4, b'joinable'),
                    (4, b'associatedDomain'),
                    (4, b'owner'),
                    (4, b'rfc822ErrorsTo'),
                    (4, b'ErrorsTo'),
                    (4, b'rfc822RequestsTo'),
                    (4, b'RequestsTo'),
                    (4, b'moderator'),
                    (4, b'labeledURL'),
                    (4, b'onVacation'),
                    (4, b'vacationMessage'),
                    (4, b'drink'),
                    (4, b'lastModifiedBy'),
                    (4, b'lastModifiedTime'),
                    (4, b'modifiersname'),
                    (4, b'modifytimestamp'),
                    (4, b'creatorsname'),
                    (4, b'createtimestamp'),
                ])
            ])
        ])
    ]


def test_utctime():
    buf = (
        '201005'  # yymndd
        '012345'  # hhmmss
        '+1234'   # +hhmm
    )
    assert utctime(buf) == 1601815785.0

    buf = (
        '201005'  # yymndd
        '012345'  # hhmmss
        '-1234'   # -hhmm
    )
    assert utctime(buf) == 1601906265.0


def test_decode():
    import pytest
    from binascii import unhexlify
    buf = unhexlify(
        '20'   # CONSTRUCTED
        '80'   # 128 | 0
        '0000' # end-of-contents
    )
    assert decode(buf) == [(32, [])]

    # indefinite-length constructed content followed by a sibling TLV
    buf = unhexlify(
        '30'       # SEQUENCE (constructed)
        '80'       # indefinite length
        '020101'   # INTEGER 1
        '0000'     # end-of-contents
        '020102'   # sibling INTEGER 2
    )
    assert decode(buf) == [(48, [(2, 1)]), (2, 2)]

    # indefinite length is illegal on primitive tags -> fail closed
    with pytest.raises(dpkt.UnpackError, match="indefinite length on primitive"):
        decode(unhexlify('02800000'))

    # missing end-of-contents -> fail closed
    with pytest.raises(dpkt.UnpackError, match="end-of-contents"):
        decode(unhexlify('3080020101'))

    # unpacking UTC_TIME
    buf = unhexlify(
        '17'  # t: code: UTC_TIME
        '81'  # l_: code: 128 | 1 (constructed
        '11'  # data len (17 octets)
        '3230313030353031323334352b30303030'

    )
    assert decode(buf) == [(23, 1601861025.0)]

    # unpacking 2-byte size; zero-length integer
    buf = unhexlify(
        '02'    # t: INTEGER
        '82'    # l_: 128 | 2
        '0000'  # new l_
    )
    assert decode(buf) == [(2, 0)]

    # unpacking 3-byte size
    buf = unhexlify(
        '02'        # t: INTEGER
        '83'        # l_: 128 | 3
        '000001'    # new l_
        '01'        # integer content
    )
    assert decode(buf) == [(2, 1)]

    # unpacking 4-byte size
    buf = unhexlify(
        '02'        # t: INTEGER
        '84'        # l_: 128 | 4
        '00000002'  # new l_
        'abcd'
    )
    assert decode(buf) == [(2, 43981)]

    # unpacking 4-byte size
    buf = unhexlify(
        '02'        # t: INTEGER
        '85'        # l_: 128 | 5
    )
    with pytest.raises(dpkt.UnpackError, match="excessive long-form ASN.1 length 133"):
        decode(buf)

    # unpacking 1-byte size; 4-byte integer
    buf = unhexlify(
        '02'        # t: INTEGER
        '81'        # l_: 128 | 1
        '04'        # new l_
        '12345678'  # integer
    )
    assert decode(buf) == [(2, 305419896)]

    # unpacking 1-byte size; 5-byte integer (arbitrary length, e.g. RSA fields)
    buf = unhexlify(
        '02'        # t: INTEGER
        '81'        # l_: 128 | 1
        '05'        # new l_
        '0102030405'
    )
    assert decode(buf) == [(2, 0x0102030405)]

    # unpacking 1-byte size; 3-byte integer (with leading zero pad)
    buf = unhexlify(
        '02'        # t: INTEGER
        '81'        # l_: 128 | 1
        '03'        # new l_
        '001234'    # integer

        '02'        # t: INTEGER
        '81'        # l_: 128 | 1
        '00'        # new l_
    )
    assert decode(buf) == [
        (2, 0x001234),
        (2, 0),
    ]


def test_decode_bounded_and_fail_closed():
    import pytest
    from binascii import unhexlify

    # long-form length claiming more bytes than the window contains:
    # previously silently truncated, now must fail closed
    with pytest.raises(dpkt.UnpackError, match="exceeds"):
        decode(unhexlify('30821000010100'))
    # same for a 1-byte long-form length
    with pytest.raises(dpkt.UnpackError, match="exceeds"):
        decode(unhexlify('048105414243'))

    # truncated type/length header and truncated long-form length
    with pytest.raises(dpkt.UnpackError, match="truncated ASN.1 header"):
        decode(b'\x30')
    with pytest.raises(dpkt.UnpackError, match="truncated ASN.1 long-form length"):
        decode(unhexlify('308200'))
    with pytest.raises(dpkt.UnpackError, match="truncated ASN.1 long-form length"):
        decode(unhexlify('30840000'))

    # junk trailing inside a constructed window is rejected (fail closed)
    with pytest.raises(dpkt.UnpackError):
        decode(unhexlify('3004020100ff'))
    # junk trailing at the top level is rejected as well
    with pytest.raises(dpkt.UnpackError):
        decode(unhexlify('3003020100ff'))

    # deep nesting is bounded by a shared depth budget instead of exhausting
    # the C stack (RecursionError must never escape)
    payload = b'\x02\x01\x00'
    for _ in range(MAX_DEPTH + 50):
        payload = b'\x30\x82' + len(payload).to_bytes(2, 'big') + payload
    with pytest.raises(dpkt.UnpackError, match="nesting depth"):
        decode(payload)

    # legal nesting well under the limit still parses
    payload = b'\x02\x01\x00'
    for _ in range(10):
        payload = b'\x30' + bytes([len(payload)]) + payload
    decoded = decode(payload)
    for _ in range(10):
        assert decoded[0][0] == 0x30  # SEQUENCE, constructed
        decoded = decoded[0][1]
    assert decoded == [(INTEGER, 0)]

    # multi-segment input (several top-level certificates/TLVs) keeps parsing
    cert_a = unhexlify('3006020101020102')
    cert_b = unhexlify('3003040141')
    assert decode(cert_a + cert_b) == [
        (48, [(2, 1), (2, 2)]),
        (48, [(4, b'A')]),
    ]

    # invalid UTCTime content fails closed instead of raising IndexError
    with pytest.raises(dpkt.UnpackError, match="UTCTime"):
        decode(unhexlify('17023132'))

    # every supported long-form size remains accepted
    assert decode(unhexlify('0281012a')) == [(2, 42)]
    assert decode(unhexlify('028200021234')) == [(2, 4660)]
    assert decode(unhexlify('0283000003000003')) == [(2, 3)]
    assert decode(unhexlify('028400000002abcd')) == [(2, 43981)]

    # 3-byte long-form length above 4095: the legacy decoder masked the high
    # byte (& 0xfff) and read out of bounds; the full length must be honored
    content = b'A' * 0x101
    assert decode(b'\x04\x83\x00\x01\x01' + content) == [(4, content)]
