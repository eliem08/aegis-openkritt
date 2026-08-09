from __future__ import annotations

import base64
import hashlib
import socket
import struct
from threading import Thread

from aegis.egress.app import _default_websocket_sender


def _read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        data.extend(stream.recv(size - len(data)))
    return bytes(data)


def _read_client_text(stream):
    first, second = _read_exact(stream, 2)
    assert first & 0x0F in {0x1, 0x8}
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", _read_exact(stream, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", _read_exact(stream, 8))[0]
    mask = _read_exact(stream, 4)
    payload = _read_exact(stream, size)
    return first & 0x0F, bytes(value ^ mask[index % 4] for index, value in enumerate(payload))


def _server_text(value):
    payload = value.encode("utf-8")
    return bytes((0x81, len(payload))) + payload


def test_default_websocket_transport_performs_real_masked_handshake_and_frames():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    observed = {}

    def serve():
        connection, _ = listener.accept()
        with connection:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(connection.recv(1024))
            text = request.decode("latin-1")
            key = next(
                line.split(":", 1)[1].strip() for line in text.split("\r\n")
                if line.lower().startswith("sec-websocket-key:")
            )
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()).decode("ascii")
            connection.sendall((
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n"
                "Sec-WebSocket-Protocol: aegis-json\r\n\r\n"
            ).encode("latin-1"))
            observed["messages"] = tuple(
                _read_client_text(connection)[1].decode("utf-8") for _ in range(3)
            )
            connection.sendall(_server_text("subscribed"))
            connection.sendall(_server_text("AEGIS-WS-CANARY-LAB"))
            connection.sendall(_server_text("state:active"))
            connection.sendall(b"\x88\x02" + struct.pack("!H", 1000))
            observed["client_close"] = _read_client_text(connection)[0]
        listener.close()

    thread = Thread(target=serve, daemon=True)
    thread.start()
    response = _default_websocket_sender(
        f"ws://socket.example.test:{port}/events",
        "127.0.0.1",
        {"authorization": "Bearer controlled", "sec-websocket-protocol": "aegis-json"},
        ["subscribe", "read", "state"],
        8,
        2.0,
    )
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert response.handshake_status == 101
    assert response.selected_protocol == "aegis-json"
    assert response.messages == ["subscribed", "AEGIS-WS-CANARY-LAB", "state:active"]
    assert response.close_code == 1000
    assert observed == {"messages": ("subscribe", "read", "state"), "client_close": 8}
