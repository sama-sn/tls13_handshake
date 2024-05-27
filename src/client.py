#!/usr/bin/env python3
import argparse
import socket
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from key_generation import get_client_keys, get_handshake_keys_ski_cki, get_hello_hash
from clienthello import client_hello

# from certificate_validation import validate_certificate_chain

serverhello = bytes()
clienthello = bytes()
hellohash = bytes()
server_handshake_key = bytes()
server_handshake_iv = bytes()
client_handshake_key = bytes()
client_handshake_iv = bytes()
client_private_key = bytes()
client_private_key_bytes = bytes()
client_public_key = bytes()
client_public_key_bytes = bytes()
recordnum = 0


def recv_size(s, size):
    buf = b""
    while len(buf) < size:
        temp = s.recv(size - len(buf))
        if not temp:
            break
        buf += temp
    return buf


def recvall(s):
    buf = b""
    while True:
        temp = s.recv(1024)
        if not temp:
            break
        buf += temp
    return buf


def jsonprint(m):
    print(
        json.dumps(
            m, indent=4, default=lambda x: x.hex() if isinstance(x, bytes) else None
        )
    )


def get_iv_xor(iv, recordnum):
    recnum_bytes = recordnum.to_bytes(len(iv), byteorder="big")
    new_iv = bytearray(len(iv))
    for i in range(len(iv)):
        new_iv[i] = iv[i] ^ recnum_bytes[i]
    return new_iv


def decrypt_aes_128_gcm(key, iv, recordnum, recdata, record, authtag):
    xor_iv = get_iv_xor(iv, recordnum)

    cipher = Cipher(algorithms.AES(key), modes.GCM(xor_iv, authtag))

    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(recdata)
    decrypted_data = decryptor.update(record) + decryptor.finalize()

    return decrypted_data


def decrypt_record(record):
    # Req encryption algo:
    global recordnum
    recdata = record[:5]
    authtag = record[-16:]
    decrypted_record = decrypt_aes_128_gcm(
        server_handshake_key,
        server_handshake_iv,
        recordnum,
        recdata,
        record[5:-16],
        authtag,
    )
    recordnum += 1
    return decrypted_record


def handle_extensions(extensions):
    extension_map = {}
    window = 0
    size = len(extensions)
    while window < size:
        extension_type = int.from_bytes(extensions[window : window + 2], "big")
        ext_size = int.from_bytes(extensions[window + 2 : window + 4], "big")
        extension = extensions[window + 4 : window + 4 + ext_size]
        extension_map[extension_type] = extension
        window += ext_size + 4
    return extension_map


def set_handshake_key_iv(server_public_key_bytes, client_private_key, hellohash):
    global server_handshake_key
    global server_handshake_iv
    global client_handshake_key
    global client_handshake_iv
    (
        server_handshake_key,
        server_handshake_iv,
        client_handshake_key,
        client_handshake_iv,
    ) = get_handshake_keys_ski_cki(
        server_public_key=server_public_key_bytes,
        client_private_key=client_private_key,
        hello_hash=hellohash,
    )


def get_handshake_key_iv():
    global server_handshake_key
    global server_handshake_iv
    global client_handshake_key
    global client_handshake_iv
    return (
        server_handshake_key,
        server_handshake_iv,
        client_handshake_key,
        client_handshake_iv,
    )


def handle_server_hello(record):
    server_version = record[0:2]
    server_random = record[2:34]
    session_id_size = record[34]
    session_id = record[35 : 35 + session_id_size]
    window = 35 + session_id_size
    cipher_suite = record[window : window + 2]
    compression_method = record[window + 2]
    extension_length = int.from_bytes(record[window + 3 : window + 5], "big")
    extension_map = handle_extensions(record[window + 5 :])
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
    key_share = extension_map[51]
    key_type = key_share[0:2]
    key_size = int.from_bytes(key_share[2:4], "big")
    server_public_key_bytes = key_share[4 : 4 + key_size]
    server_hello_map = {
        "server_random": server_random,
        "cipher_suite": cipher_suite,  # https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
        "compression_method": compression_method,
        "key_type": key_type,
        "server_public_key": server_public_key_bytes,
    }
    # jsonprint(server_hello_map)
    # depends on the cipher suite:
    set_handshake_key_iv(server_public_key_bytes, client_private_key, hellohash)
    return server_hello_map


def set_serverhello(record):
    global serverhello
    serverhello = record


def set_clienthello(record):
    global clienthello
    clienthello = record


def set_hellohash():
    global hellohash
    hellohash = get_hello_hash(clienthello, serverhello)


def handle_server_certificates(message):
    window = message[0]
    request_context = message[1 : 1 + window]
    certs_len = int.from_bytes(message[window + 1 : window + 4], "big")
    window += 4
    certs = []
    extensions = []  # Not handling certificate extenstions. Jut collecting
    while window < certs_len:
        cert_len = int.from_bytes(message[window : window + 3], "big")
        window += 3
        cert = message[window : window + cert_len]
        certs.append(cert)
        window += cert_len
        cert_extension_len = int.from_bytes(message[window : window + 2], "big")
        window += 2
        extensions.append(message[window : window + cert_extension_len])
    return certs


def handle_handshake_record(record):
    message_type = record[0]
    message = record[4:]
    match message_type:
        case 0x02:  # server hello
            set_serverhello(record)
            set_hellohash()
            ret_val = {"Server Hello": handle_server_hello(message)}
            val = {
                "Server handshake key": server_handshake_key,
                "Server handshake iv": server_handshake_iv,
                "Client handshake key": client_handshake_key,
                "Client handshake iv": client_handshake_iv,
            }
            ret_val["Keys"] = val
            return ret_val
        case 0x08:  # Encrypted extensions
            return {"Server Encrypted Extensions": message}
        case 0x0B:  # Server Certificate
            return {"Server Certificates": handle_server_certificates(message)}
        case 0x0F:  # Certificate verify
            server_cert = x509.load_der_x509_certificate(message)
            valid, message = validate_certificate_chain(server_cert)
            return {"Certificate Verify": [valid, message]}
        case 0x14:  # Server Handshake Finished
            return {"Server Handshake Finished": message}  # !!! INCOMPLETE
        case _:
            return {"Unhandled handshake record": message}


def handle_wrapped_record(record):
    decrypted_record = decrypt_record(record)
    record_type = decrypted_record[-1]
    match record_type:
        case 0x16:
            return handle_handshake_record(decrypted_record[:-1])
        case 0x15:
            return {"Alert record received": decrypted_record.hex()}
        case _:
            return {"Unhandled wrapped record(decrypted:)": decrypted_record.hex()}


def handle_server_response(response):
    window = 0
    response_size = len(response)
    server_responses = {}
    while window < response_size:
        record_size = int.from_bytes(response[window + 3 : window + 5], "big")
        record = response[window : window + 5 + record_size]
        record_type = response[window]
        match record_type:
            case 0x14:
                result = {"Server Change Sipher Spec": "-"}
            case 0x16:
                result = handle_handshake_record(record[5:])
            case 0x17:
                # server_responses.append({"Wrapped": record.hex()})
                result = handle_wrapped_record(record)
            case _:
                result = {"Unknown": record}
        window += 5 + record_size
        # jsonprint(result)
        server_responses.update(result)
    return server_responses


def main():
    global recordnum
    recordnum = 0
    global client_private_key, client_public_key, client_public_key_bytes, client_private_key_bytes
    (
        client_private_key,
        client_public_key,
        client_private_key_bytes,
        client_public_key_bytes,
    ) = get_client_keys()
    client_random = secrets.token_bytes(32)

    # hostname, port = "wkr.io", i # 167.99.54.57:1503
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "host_port", help="Example: example.com:443 or 0.0.0.0:8080"
    )
    hostport = (arg_parser.parse_args()).host_port
    hostname, port = hostport.split(":")
    port = int(port)

    s = socket.socket()
    s.connect((hostname, port))

    # clienthello = client_hello(client_random, client_public_key_bytes, hostname)
    clienthello = client_hello(client_random, client_public_key_bytes)
    set_clienthello(clienthello[5:])
    s.sendall(clienthello)
    server_response = recvall(s)
    server_responses = handle_server_response(server_response)
    output = {"Client Hello": clienthello}
    output.update(server_responses)
    jsonprint(output)

    # (is_valid, valid_message) = validate_certificate_chain(
    #     server_responses["Server Certificates"][0]
    # )
    # if is_valid:
    #     print("certificate is valid.")
    # else:
    #     print("certificate is invalid: " + valid_message)
    s.close()


if __name__ == "__main__":
    main()
