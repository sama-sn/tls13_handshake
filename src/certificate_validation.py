from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
import datetime
from pathlib import Path


def load_certificate_from_file(file_path):
    with open(file_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


# Verify that CN of server's certificate is what we expect
def verify_subject_cn(server_cert, expected_cn):
    # Extract the subject from the certificate
    subject = server_cert.subject

    # Find the CN attribute in the subject
    common_name_attr = next(
        (x for x in subject if x.oid == x509.NameOID.COMMON_NAME), None
    )

    # Verify the CN attribute matches the expected Common Name
    validity = common_name_attr and common_name_attr.value == expected_cn
    if validity:
        return validity, ""
    else:
        return (
            validity,
            f"Certificate's Common Name (CN) is invalid. Expected: {expected_cn}, Received: {common_name_attr.value}\n",
        )


def get_authority_key_identifier(cert):
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    return ext.value.key_identifier


def get_subject_key_identifier(cert):
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return ext.value.digest


# Verify authority key identifier of server cert matches subject key identifier of CA cert
def verify_authority_key_identifier(server_cert, ca_cert):
    server_auth_key_id = get_authority_key_identifier(server_cert)
    ca_subject_key_id = get_subject_key_identifier(ca_cert)
    validity = server_auth_key_id == ca_subject_key_id
    if validity:
        return validity, ""
    else:
        return (
            validity,
            f"The AuthorityKeyIdentifier does not match the SubjectKeyIdentifier of the CA.\n",  # Expected: {ca_subject_key_id.hex()}, Received: {server_auth_key_id.hex()}\n
        )


# Verify signature of server's certificate
def verify_certificate_signature(server_cert, ca_cert):
    try:
        # Extract the public key from the CA certificate
        ca_public_key = ca_cert.public_key()

        # Verify the server's certificate signature with the CA's public key
        ca_public_key.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            ec.ECDSA(server_cert.signature_hash_algorithm),
        )
        return True, ""
    except InvalidSignature:
        return False, "Certificate signature is invalid.\n"


def return_cert_validity(checks):
    token = True
    message = ""
    for t, m in checks:
        token = token and t
        message += m
    return token, message


def validate_certificate_chain(
    cert_bin, ca_cert=load_certificate_from_file(Path(__file__).parent / "ca1.pem")
):
    server_cert = x509.load_der_x509_certificate(cert_bin, default_backend())

    try:
        # Verify that the issuer of the server's certificate matches the subject of the CA certificate
        token = True
        message = ""
        if server_cert.issuer != ca_cert.subject:
            token = token and False
            message += (
                "Certificate chain is invalid: issuer does not match CA's subject.\n"
            )
        # Verify that CN of server's certificate is tls.example.com
        # Verify authority key identifier of server cert matches subject key identifier of CA cert
        # Verify signature of server's certificate
        checks = [
            (token, message),
            verify_subject_cn(server_cert, "tls.example.com"),
            verify_authority_key_identifier(server_cert, ca_cert),
            verify_certificate_signature(server_cert, ca_cert),
        ]

        # Check the validity period of the server's certificate
        if server_cert.not_valid_before > server_cert.not_valid_after:
            checks.append(
                (
                    False,
                    f"Certificate's validity period is invalid. Not valid before: {server_cert.not_valid_before}, and Not valid after: {server_cert.not_valid_after}\n",
                )
            )

        # Check the current time is within the validity period
        time_now = datetime.datetime.now()
        if (
            server_cert.not_valid_before > time_now
            or server_cert.not_valid_after < time_now
        ):
            checks.append(
                (
                    False,
                    f"Certificate is not currently valid. Not valid before: {server_cert.not_valid_before}, and Not valid after: {server_cert.not_valid_after}. Current time: {time_now}\n",
                )
            )
        token, message = return_cert_validity(checks)
        if token:
            return True, "Certificate is valid."
        else:
            return token, message
    except Exception as e:
        return False, str(e)
