"""Synthetic R2SF images and signed packages for the firmware tests."""
import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# The signed-package tag magic, from the observed AD1204 0073 package (docs/firmware-research.md).
MAGIC = bytes.fromhex("000000004d49ef54464f544182562647")


def raw_image():
    """Return a 1 KiB R2SF image with image base 0x403000 at offset 0x24."""
    image = bytearray(1024)
    struct.pack_into("<II", image, 0, 0x20047458, 0x403059)
    struct.pack_into("<I", image, 0x24, 0x403000)
    image[40:44] = b"R2SF"
    return bytes(image)


def image(signed=True, pid=0x660E, cert_size=8, tail=b"c" * 8 + b"signature", tlv=None, tag_size=None):
    """Return a raw image, or the image, the AD1204 tag and ``tail`` (certificates and signature).

    The tag TLVs are version 2.1.2 build 0x0049 (``2.1.2_0073``) and model ``njcuk.fitting.ad1204``,
    unless ``tlv`` gives other TLV bytes. ``tag_size`` overrides the declared tag size.
    """
    raw = bytearray(1024)
    struct.pack_into("<II", raw, 0, 0x20047458, 0x403059)
    raw[40:44] = b"R2SF"
    if not signed:
        return bytes(raw)
    if tlv is None:
        tlv = b"\x01\x05\x02\x01\x02\x49\x00" + b"\x04\x14njcuk.fitting.ad1204"
    tag_size = tag_size or 28 + len(tlv) + 4
    tag = MAGIC + struct.pack("<HHIHBB", tag_size, pid, len(raw), cert_size, 0, 0) + tlv + b"\0" * 4
    return bytes(raw) + tag + tail


def _certificate(name, public_key, issuer_name, issuer_key):
    now = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
            .public_key(public_key).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(issuer_key, hashes.SHA256()))


def signed_package(forge=None):
    """Return a signed package with a new P-256 server and developer key pair.

    The developer key signs the image and the tag with ECDSA-SHA256. The server key signs the
    developer certificate. ``forge`` makes one part not valid:

    - ``"image"``: an unrelated key signs the image.
    - ``"developer"``: an unrelated key signs the developer certificate.
    - ``"one-certificate"``: the package has only the developer certificate.
    """
    server_key = ec.generate_private_key(ec.SECP256R1())
    developer_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    server = _certificate("server", server_key.public_key(), "server", server_key)
    developer = _certificate("developer", developer_key.public_key(), "server",
                             other_key if forge == "developer" else server_key)
    certificates = [developer] if forge == "one-certificate" else [server, developer]
    pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certificates)
    signed_part = image(cert_size=len(pem), tail=b"")
    signer = other_key if forge == "image" else developer_key
    return signed_part + pem + signer.sign(signed_part, ec.ECDSA(hashes.SHA256()))
