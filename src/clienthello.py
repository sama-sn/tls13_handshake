import secrets
import socket
from key_generation import get_client_keys, get_public_bytes, get_private_bytes


def tls_header(length: int):
    content_type = b"\x16"  # handshake
    version = b"\x03\x01"  # tls 1.0
    return content_type + version + length.to_bytes(2, byteorder="big")


def servername_ext(hostname: str) -> bytes:
    ext_type = b"\x00\x00"
    url_bytes = len(hostname).to_bytes(2, byteorder="big") + hostname.encode()
    # type dns hostname + hostname
    packet = b"\x00" + url_bytes
    # list entry length + list entry
    packet = len(packet).to_bytes(2, byteorder="big") + packet
    # extension data length + extension data
    packet = len(packet).to_bytes(2, byteorder="big") + packet
    # extension type + extension
    packet = ext_type + packet
    return packet


def client_hello(session_id: bytes, public_key: bytes):
    handshake_type = b"\x01"  # client hello
    version = b"\x03\x03"  # tls 1.2
    random = secrets.token_bytes(32)
    # TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_GCM_SHA25
    # cipher_suites = b"\x13\x02\x13\x03\x13\x01"
    cipher_suites = (
        b"\x13\x01\x13\x03\x13\x02\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c"
        + b"\xc0\x30\xc0\x0a\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f"
        + b"\x00\x35"
    )
    compression_methods = b"\x01\x00"  # null
    extensions = []
    # sni
    # extensions.append(servername_ext(hostname))
    # support elliptic curve data points
    extensions.append(b"\x00\x0b" + b"\x00\x02" + b"\x01" + b"\x00")
    # supported groups: x25519
    # extensions.append(b"\x00\x0a" + b"\x00\x04" + b"\x00\x02" + b"\x00\x1d")
    extensions.append(
        b"\x00\x0a\x00\x0e\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01"
    )
    # no session ticket
    extensions.append(b"\x00\x23\x00\x00")
    # signature algorithms: ecdsa-secp384r1-sha256/384/512
    extensions.append(
        b"\x00\x0d"
        + b"\x00\x08"
        + b"\x00\x06"
        + b"\x04\x03"
        + b"\x05\x03"
        + b"\x06\x03"
    )
    # supported versions: tls 1.3
    extensions.append(b"\x00\x2b" + b"\x00\x05" + b"\x04" + b"\x03\x04" + b"\x03\x03")
    # key share
    extensions.append(
        b"\x00\x33" + b"\x00\x26" + b"\x00\x24" + b"\x00\x1d" + b"\x00\x20" + public_key
    )

    extensions_bytes = b""
    for e in extensions:
        extensions_bytes += e
    handshake_packet = (
        version
        + random
        + len(session_id).to_bytes(1, byteorder="big")
        + session_id
        + len(cipher_suites).to_bytes(2, byteorder="big")
        + cipher_suites
        + compression_methods
        + len(extensions_bytes).to_bytes(2, byteorder="big")
        + extensions_bytes
    )
    tls_packet = (
        handshake_type
        + len(handshake_packet).to_bytes(3, byteorder="big")
        + handshake_packet
    )
    packet = tls_header(len(tls_packet)) + tls_packet
    return packet
