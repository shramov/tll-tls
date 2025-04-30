#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import decorator
import pytest
import socket
import ssl

from tll.test_util import ports

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

    s.post(b'xxx', addr=addr)
    m = await c.recv()

    assert m.data.tobytes() == b'xxx'

    c.post(b'yyy')
    m = await s.recv()

    assert m.data.tobytes() == b'yyy'

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

    s.post(b'xxx', addr=m.addr)
    assert ssock.read() == b'xxx'

    ssock.write(b'yyy')
    m = await s.recv()

    assert m.data.tobytes() == b'yyy'

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
