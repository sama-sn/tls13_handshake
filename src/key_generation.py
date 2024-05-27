from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import hashlib

server_public_key = bytes()
server_public_key_bytes = bytes()
hello_hash = bytes()
client_private_key = bytes()
client_public_key = bytes()
client_public_key_bytes = bytes()
client_private_key_bytes = bytes()
# 32 0s. bytes([32]) 32 represented in bytes. int_val.to_bytes(1) - 1 byte representation

hash_function = hashlib.sha256
hkdf_algo = hashes.SHA256()
zero_key = bytes(hkdf_algo.digest_size)
empty_hash = hash_function("".encode()).digest()


# we use salt as the key for hashing
def hkdf_extract(salt: bytes, msg: bytes) -> bytes:
    hmac = HMAC(salt, hkdf_algo)
    hmac.update(msg)
    return hmac.finalize()


def hkdf_expand(key_material: bytes, info: bytes, length: int):
    hkdf = HKDFExpand(
        algorithm=hkdf_algo,
        length=length,
        info=info,
    )
    key = hkdf.derive(key_material)
    return key


# expand-label should do:
# hex({length}) hex({label_len+6}) hex("tls13 {label}") hex({ctx_len}) hex({ctx}) as info for expand with prk=key
def hkdf_expand_label(key: bytes, label: str, ctx: bytes, length: int) -> bytes:
    label = "tls13 " + label
    label_len = len(label).to_bytes(1, "big")
    ctx_len = len(ctx).to_bytes(1, "big")
    info = length.to_bytes(2, "big") + label_len + label.encode() + ctx_len + ctx
    return hkdf_expand(key, info, length)


def get_handshake_secret(shared_secret):
    early_secret = hkdf_extract(zero_key, zero_key)
    derived_secret = hkdf_expand_label(
        key=early_secret, label="derived", ctx=empty_hash, length=32
    )
    handshake_secret = hkdf_extract(derived_secret, shared_secret)
    return handshake_secret


def get_key(secret):
    return hkdf_expand_label(key=secret, label="key", ctx="".encode(), length=16)


def get_iv(secret):
    return hkdf_expand_label(key=secret, label="iv", ctx="".encode(), length=12)


def get_sksi_ckci_keys(
    handshake_secret,
    hello_hash,
    client_label="c hs traffic",
    server_label="s hs traffic",
):
    client_secret = hkdf_expand_label(
        key=handshake_secret, label=client_label, ctx=hello_hash, length=32
    )
    # bcs we don't have the "info" param ssecret and csecret will be same?
    server_secret = hkdf_expand_label(
        key=handshake_secret, label=server_label, ctx=hello_hash, length=32
    )

    client_handshake_key = get_key(client_secret)
    server_handshake_key = get_key(server_secret)
    client_handshake_iv = get_iv(client_secret)
    server_handshake_iv = get_iv(server_secret)

    return (
        server_handshake_key,
        server_handshake_iv,
        client_handshake_key,
        client_handshake_iv,
    )


def get_master_secret(handshake_secret):
    derived_secret = hkdf_expand_label(
        key=handshake_secret, label="derived", ctx=empty_hash, length=48
    )
    master_secret = hkdf_extract(derived_secret, zero_key)
    return master_secret


def get_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,  # Allows serialization of the key to bytes. Encoding ( PEM, DER, or Raw)
        format=serialization.PublicFormat.Raw,  # print(binascii.hexlify(public_key_bytes))
    )


def get_private_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,  # Allows serialization of the key to bytes. Encoding ( PEM, DER, or Raw)
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def get_hello_hash(clienthello: bytes, serverhello: bytes) -> bytes:
    if clienthello[0] == 0x16:
        clienthello = clienthello[5:]
    if serverhello[0] == 0x16:
        serverhello = serverhello[5:]
    message = clienthello + serverhello
    sha384_hash = (hash_function(message)).digest()  # use hexdigest() to print/view
    return sha384_hash


def get_handshake_hash(
    clienthello,
    serverhello,
    serverextenstions,
    servercert,
    servercertverify,
    serverfinished,
):
    message = (
        clienthello[5:]
        + serverhello[5:]
        + serverextenstions
        + servercert
        + servercertverify
        + serverfinished
    )
    sha384_hash = (
        hash_function(message.encode())
    ).hexdigest()  # use digest() for byte array
    return sha384_hash  # todo


# returns private and public keys
def get_client_keys():
    global client_private_key, client_public_key, client_public_key_bytes, client_private_key_bytes
    client_private_key = x25519.X25519PrivateKey.generate()
    client_public_key = client_private_key.public_key()
    client_public_key_bytes = get_public_bytes(client_public_key)
    client_private_key_bytes = get_private_bytes(client_private_key)

    return (
        client_private_key,
        client_public_key,
        client_private_key_bytes,
        client_public_key_bytes,
    )


def get_shared_secret(client_private_key, server_public_key):
    shared_secret = client_private_key.exchange(server_public_key)
    return shared_secret


def get_handshake_keys_ski_cki(
    server_public_key=server_public_key,
    client_private_key=client_private_key,
    hello_hash=hello_hash,
):
    if isinstance(server_public_key, bytes):
        server_public_key = X25519PublicKey.from_public_bytes(server_public_key)
    if isinstance(client_private_key, bytes):
        client_private_key = X25519PrivateKey.from_private_bytes(client_private_key)
    shared_secret = get_shared_secret(client_private_key, server_public_key)
    handshake_secret = get_handshake_secret(shared_secret)
    return get_sksi_ckci_keys(handshake_secret, hello_hash)


def get_app_keys_ski_cki(handshake_secret, handshake_hash):
    master_secret = get_master_secret(handshake_secret)
    return get_sksi_ckci_keys(
        master_secret, handshake_hash, "c app traffic", "s app traffic"
    )


"""
References:
https://tls13.xargs.org/#server-application-keys-calc
https://stackoverflow.com/questions/71879203/curve-25519-symmetric-key-with-python
https://en.wikipedia.org/wiki/HKDF # removed
    updated with: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf
Sha384() from hashlib: https://docs.python.org/3/library/hashlib.html

hkdf_expand based on the hkdf-384.sh file:
"""

# HOW TO USE:
# get_client_keys returns private, public keys
# get_hello_hash(clienthell,serverhello) - removes the record header and returns the hello_hash
# get_handshke_keys_ski_cki # return handshake server key, iv, client key, iv
# def get_app_keys # not req for the assignment
