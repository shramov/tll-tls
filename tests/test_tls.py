#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import decorator
import pytest
import socket
import ssl
import struct

from tll.error import TLLError
from tll.test_util import Accum, ports

@decorator.decorator
def asyncloop_run(f, asyncloop, *a, **kw):
    asyncloop.run(f(asyncloop, *a, **kw))

@asyncloop_run
async def test(asyncloop):
    s = asyncloop.Channel(f'tls://::1:{ports.TCP6};mode=server', name='server', dump='yes', cert='cert/server.pem', key='cert/server.key', ca='cert/ca.pem')
    c = asyncloop.Channel(f'tls://::1:{ports.TCP6};mode=client', name='client', dump='yes', cert='cert/client.pem', key='cert/client.key', ca='cert/ca.pem')

    s.open()
    c.open()

    assert (await c.recv_state()) == c.State.Active

    m = await s.recv()
    assert m.type == m.Type.Control
    assert s.unpack(m).subject == '/O=tll-tls/OU=test/CN=client'
    addr = m.addr

    s.post(b'xxx', msgid=10, seq=100, addr=addr)
    m = await c.recv()

    assert (m.msgid, m.seq, m.data.tobytes()) == (10, 100, b'xxx')

    c.post(b'yyy', msgid=20, seq=200)
    m = await s.recv()

    assert (m.msgid, m.seq, m.data.tobytes()) == (20, 200, b'yyy')

@asyncloop_run
async def test_server(asyncloop):
    s = asyncloop.Channel(f'tls://::1:{ports.TCP6};mode=server', name='server', dump='yes', cert='cert/server.pem', key='cert/server.key', ca='cert/ca.pem')
    s.open()

    sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    sock.settimeout(0.1)
    sock.connect(('::1', ports.TCP6))
    sock.setblocking(False)

    for _ in range(10):
        s.children[0].process()

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sslctx.load_verify_locations('cert/ca.pem')
    sslctx.load_cert_chain('cert/client.pem', 'cert/client.key')
    sslctx.check_hostname = False

    ssock = sslctx.wrap_socket(sock, do_handshake_on_connect=False)
    for _ in range(10):
        s.children[-1].process()
        try:
            ssock.read()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            pass
    assert ssock.getpeercert()['subject'] == ((('organizationName', 'tll-tls'),), (('organizationalUnitName', 'test'),), (('commonName', 'server'),))

    m = await s.recv()
    assert m.type == m.Type.Control
    assert s.unpack(m).subject == '/O=tll-tls/OU=test/CN=client'

    s.post(b'xxx', msgid=10, seq=100, addr=m.addr)
    assert ssock.read(16) == struct.pack('Iiq', 3, 10, 100)
    assert ssock.read() == b'xxx'

    ssock.write(struct.pack('Iiq', 3, 20, 200) + b'yyy')
    m = await s.recv()

    assert (m.msgid, m.seq, m.data.tobytes()) == (20, 200, b'yyy')

@pytest.mark.parametrize('cert', [None, 'reject'])
def test_server_reject(context, cert):
    s = context.Channel(f'tls://::1:{ports.TCP6};mode=server', name='server', dump='yes', cert='cert/server.pem', key='cert/server.key', ca='cert/ca.pem')
    s.open()

    sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    sock.settimeout(0.1)
    sock.connect(('::1', ports.TCP6))
    sock.setblocking(False)

    for _ in range(10):
        s.children[0].process()

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sslctx.load_verify_locations('cert/ca.pem')
    if cert:
        sslctx.load_cert_chain(f'cert/{cert}.pem', f'cert/{cert}.key')
    sslctx.check_hostname = False

    ssock = sslctx.wrap_socket(sock, do_handshake_on_connect=False)
    for _ in range(10):
        try:
            s.children[-1].process()
        except:
            break
        try:
            ssock.read()
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            pass

    with pytest.raises(ssl.SSLError): ssock.read() # Connection terminated

def test_large(context):
    s = Accum(f'tls://::1:{ports.TCP6};mode=server', name='server', dump='frame', cert='cert/server.pem', key='cert/server.key', ca='cert/ca.pem', context=context)
    c = Accum(f'tls://::1:{ports.TCP6};mode=client', name='client', dump='frame', cert='cert/client.pem', key='cert/client.key', ca='cert/ca.pem', context=context)

    s.open()
    c.open()

    for _ in range(100):
        if c.state == c.State.Active and s.result != []:
            break
        c.process()
        for i in s.children:
            i.process()

    assert [s.unpack(m).subject for m in s.result] == ['/O=tll-tls/OU=test/CN=client']
    addr = s.result[-1].addr

    s.post(b'abcdefgh' * 7 * 1024, addr=addr)

    for _ in range(5): # Frame + 4 records
        c.process()
    assert [m.data.tobytes() for m in c.result] == [b'abcdefgh' * 7 * 1024]

def test_buffered(context):
    s = Accum(f'tls://::1:{ports.TCP6};mode=server', name='server', dump='frame', cert='cert/server.pem', key='cert/server.key', ca='cert/ca.pem', context=context, sndbuf='32kb')
    c = Accum(f'tls://::1:{ports.TCP6};mode=client', name='client', dump='frame', cert='cert/client.pem', key='cert/client.key', ca='cert/ca.pem', context=context)

    s.open()
    c.open()

    for _ in range(100):
        if c.state == c.State.Active and s.result != []:
            break
        c.process()
        for i in s.children:
            i.process()

    assert [s.unpack(m).subject for m in s.result] == ['/O=tll-tls/OU=test/CN=client']
    addr = s.result[-1].addr
    s.result = []

    for i in range(10):
        s.post(b'0123456789abcde' * 1024, seq=i, addr=addr) # 15kb to fit into SSL packet
        if s.result:
            break
    assert [(m.type, m.msgid) for m in s.result] == [(s.Type.Control, s.scheme_control['WriteFull'].msgid)]
    assert (s.children[-1].dcaps & s.DCaps.PollOut) == s.DCaps.PollOut

    for _ in range(i):
        c.process()

    assert [m.seq for m in c.result] == list(range(i))
    c.process()
    assert [m.seq for m in c.result] == list(range(i))

    s.result = []
    s.children[-1].process()
    assert [(m.type, m.msgid) for m in s.result] == [(s.Type.Control, s.scheme_control['WriteReady'].msgid)]

    c.process()
    assert [m.seq for m in c.result] == list(range(i + 1))

    for j in range(i + 1):
        assert (c.result[j].seq, c.result[j].data.tobytes()) == (j, b'0123456789abcde' * 1024)

@asyncloop_run
async def test_frame_none(asyncloop):
    s = asyncloop.Channel(f'tls://::1:{ports.TCP6};mode=server;frame=none', name='server', dump='yes', cert='cert/server.pem', key='cert/server.key', ca='cert/ca.pem')
    c = asyncloop.Channel(f'tls://::1:{ports.TCP6};mode=client;frame=none', name='client', dump='yes', cert='cert/client.pem', key='cert/client.key', ca='cert/ca.pem')

    s.open()
    c.open()

    assert await c.recv_state() == c.State.Active
    m = await s.recv()
    assert m.type == m.Type.Control

    c.post(b'abc', seq=1, msgid=10)
    c.post(b'def', seq=2, msgid=20)

    m = await s.recv()
    assert (m.msgid, m.seq, m.data.tobytes()) == (0, 0, b'abc')
    m = await s.recv()
    assert (m.msgid, m.seq, m.data.tobytes()) == (0, 0, b'def')
