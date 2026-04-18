# -*- coding: utf-8 -*-
import subprocess
import traceback
import os
import base64
from flask import Flask, request, Response
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from asn1crypto import cms, core, x509 as asn1_x509
from cryptography import x509

app = Flask(__name__)

# Шляхи до ваших сертифікатів
CA_CERT_PATH = "myRoot.crt"
INT_CERT_PATH = "myIntermediate.crt"
INT_KEY_PATH = "myIntermediate.key"
RA_CERT_PATH = "myRA.crt"
RA_KEY_PATH = "myRA.key"

# SCEP OIDs
OID_MESSAGE_TYPE = "2.16.840.1.113733.1.9.2"
OID_PKI_STATUS = "2.16.840.1.113733.1.9.3"
OID_SENDER_NONCE = "2.16.840.1.113733.1.9.5"
OID_RECIPIENT_NONCE = "2.16.840.1.113733.1.9.6"
OID_TRANSACTION_ID = "2.16.840.1.113733.1.9.7"


# -------------------------------
# ASN.1 Helpers
# -------------------------------


def load_asn1_cert(path):
    with open(path, "rb") as f:
        from cryptography import x509 as crypto_x509

        cert_data = f.read()
        if b"BEGIN CERTIFICATE" in cert_data:
            c = crypto_x509.load_pem_x509_certificate(cert_data)
        else:
            c = crypto_x509.load_der_x509_certificate(cert_data)
        return asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER))


# -------------------------------
# Core Logic
# -------------------------------


def build_scep_response(enveloped_data_der, nonce_bytes, trans_id_str):
    """
    Build a CMS SignedData SCEP response wrapping an EnvelopedData payload.

    Parameters
    ----------
    enveloped_data_der : bytes
        DER-encoded EnvelopedData (full ContentInfo from openssl cms -encrypt).
    nonce_bytes : bytes
        Sender nonce extracted from the client request (becomes RecipientNonce).
    trans_id_str : str
        Transaction ID string extracted from the client request.
    """
    if nonce_bytes is None:
        raise ValueError("SenderNonce attribute missing from client request")
    if trans_id_str is None:
        raise ValueError("TransactionID attribute missing from client request")

    with open(RA_KEY_PATH, "rb") as f:
        ra_key = serialization.load_pem_private_key(f.read(), None)

    ra_cert = load_asn1_cert(RA_CERT_PATH)
    int_cert = load_asn1_cert(INT_CERT_PATH)
    ca_cert = load_asn1_cert(CA_CERT_PATH)

    # Digest over the raw EnvelopedData bytes that will sit in encapContentInfo
    digest = hashes.Hash(hashes.SHA512())
    digest.update(enveloped_data_der)
    content_digest = digest.finalize()

    # ------------------------------------------------------------------
    # FIX 1: wrap enveloped_data_der in OctetString so asn1crypto
    # encodes it correctly inside EncapsulatedContentInfo.content
    # ------------------------------------------------------------------
    encap_content = core.ParsableOctetString(enveloped_data_der)

    # Build signed attributes.
    # asn1crypto sorts CMSAttributes by OID automatically on .dump().
    attr_list = [
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [content_digest]}),
        cms.CMSAttribute(
            {"type": OID_MESSAGE_TYPE, "values": [core.PrintableString("3")]}
        ),
        cms.CMSAttribute(
            {"type": OID_PKI_STATUS, "values": [core.PrintableString("0")]}
        ),
        cms.CMSAttribute({"type": OID_RECIPIENT_NONCE, "values": [nonce_bytes]}),
        cms.CMSAttribute({"type": OID_TRANSACTION_ID, "values": [trans_id_str]}),
        # cms.CMSAttribute(
        #     {"type": OID_RECIPIENT_NONCE, "values": [core.OctetString(nonce_bytes)]}
        # ),
        # cms.CMSAttribute(
        #     {
        #         "type": OID_TRANSACTION_ID,
        #         "values": [core.PrintableString(trans_id_str)],
        #     }
        # ),
    ]
    
    attr_list = [
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [content_digest]}),
        cms.CMSAttribute({"type": OID_MESSAGE_TYPE, "values": [core.PrintableString("3")]}),
        cms.CMSAttribute({"type": OID_PKI_STATUS, "values": [core.PrintableString("0")]}),
        cms.CMSAttribute({"type": OID_RECIPIENT_NONCE, "values": [nonce_bytes]}), # nonce_bytes вже об'єкт
        cms.CMSAttribute({"type": OID_TRANSACTION_ID, "values": [trans_id_str]}), # trans_id_str вже об'єкт
    ]    

    attrs = cms.CMSAttributes(attr_list)
    # signed_attrs_der = attrs.dump()
    signed_attrs_der = attrs.dump(force=True)

    # Correct the IMPLICIT [0] tag to SET (0xA0 -> 0x31) before signing
    if signed_attrs_der[0] == 0xA0:
        signed_attrs_der = b"\x31" + signed_attrs_der[1:]

    # Sign
    signature_bytes = ra_key.sign(signed_attrs_der, ec.ECDSA(hashes.SHA512()))

    # ------------------------------------------------------------------
    # FIX 3: SignerInfo.signature is an OCTET STRING (RFC 5652 §5.3),
    # NOT a BIT STRING.  Pass raw bytes; asn1crypto types it correctly.
    # ------------------------------------------------------------------
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": ra_cert.issuer,
                            "serial_number": ra_cert.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": {"algorithm": "sha512"},
            "signed_attrs": attrs,
            "signature_algorithm": {"algorithm": "sha512_ecdsa"},
            "signature": signature_bytes,  # OctetString — not BitString
        }
    )

    # ------------------------------------------------------------------
    # FIX 4: SignedData.version must be v3 when the certificates bag
    # contains v3 certificates (RFC 5652 §5.1).
    # ------------------------------------------------------------------
    signed_data = cms.SignedData(
        {
            "version": "v1",  # was "v1" — wrong when certs are v3
            "digest_algorithms": [{"algorithm": "sha512"}],
            "encap_content_info": {
                "content_type": "data",
                "content": core.OctetString(enveloped_data_der),  # OctetString-wrapped bytes
            },
            # "certificates": [ra_cert, int_cert, ca_cert],
            "certificates": [ra_cert],
            "signer_infos": [signer_info],
        }
    )

    content_info = cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    )

    return content_info.dump()


def handle_pki_operation(data):
    # Use PID to avoid file collisions under parallel requests.
    # NOTE: pid was previously hard-coded to 0, which caused collisions.
    pid = 0  # os.getpid()
    req_file = f"req_{pid}.der"
    env_file = f"env_{pid}.der"
    inner_file = f"inner_{pid}.raw"
    csr_file = f"csr_{pid}.der"
    dev_crt = f"device_{pid}.crt"
    dev_der = f"device_{pid}.der"
    full_env = f"full_env_{pid}.der"

    try:
        with open(req_file, "wb") as f:
            f.write(data)

        # Parse signed attributes from the inbound SCEP request
        pki_msg = cms.ContentInfo.load(data)
        signed_data = pki_msg["content"]
        attrs = signed_data["signer_infos"][0]["signed_attrs"]

        nonce_bytes = None
        trans_id_str = None
        # for attr in attrs:
        #     oid = attr["type"].native
        #     if oid == OID_SENDER_NONCE:
        #         # .native on OctetString returns bytes
        #         nonce_bytes = attr["values"][0].native
        #     if oid == OID_TRANSACTION_ID:
        #         # ----------------------------------------------------------
        #         # FIX 5: extract as a plain Python str so the outbound
        #         # PrintableString is built from a known, clean type.
        #         # ----------------------------------------------------------
        #         trans_id_str = attr["values"][0].native
        raw_trans_id_obj = None
        raw_nonce_obj = None
        for attr in attrs:
            oid = attr["type"].native
            if oid == OID_TRANSACTION_ID:
                # Зберігаємо ПОВНИЙ об'єкт (разом з тегом і довжиною)
                raw_trans_id_obj = attr["values"][0]
            if oid == OID_SENDER_NONCE:
                raw_nonce_obj = attr["values"][0]

        # 1. Verify (skip chain / signature checks) to extract EnvelopedData
        subprocess.run(
            [
                "openssl",
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                req_file,
                "-nosigs",
                "-noverify",
                "-out",
                env_file,
            ],
            check=True,
            capture_output=True,
        )

        # 2. Decrypt EnvelopedData
        subprocess.run(
            [
                "openssl",
                "cms",
                "-decrypt",
                "-inform",
                "DER",
                "-in",
                env_file,
                "-recip",
                RA_CERT_PATH,
                "-inkey",
                RA_KEY_PATH,
                "-out",
                inner_file,
            ],
            check=True,
            capture_output=True,
        )

        with open(inner_file, "rb") as f:
            raw_inner = f.read()
            idx = raw_inner.find(b"\x30")  # Find start of CSR SEQUENCE
            if idx == -1:
                raise ValueError("Invalid CSR format in decrypted data")
            csr_data = raw_inner[idx:]

        with open(csr_file, "wb") as f:
            f.write(csr_data)

        # 3. Issue device certificate
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-days",
                "3650",
                "-sha512",
                "-in",
                csr_file,
                "-inform",
                "DER",
                "-CA",
                INT_CERT_PATH,
                "-CAkey",
                INT_KEY_PATH,
                "-CAcreateserial",
                "-out",
                dev_crt,
                "-extfile",
                "device_ext.cnf",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            ["openssl", "x509", "-in", dev_crt, "-outform", "DER", "-out", dev_der],
            check=True,
            capture_output=True,
        )

        # 4. Encrypt the issued cert for the device
        subprocess.run(
            [
                "openssl",
                "cms",
                "-encrypt",
                "-binary",
                "-aes256",
                "-in",
                dev_der,
                "-recip",
                dev_crt,
                "-outform",
                "DER",
                "-out",
                full_env,
            ],
            check=True,
            capture_output=True,
        )

        with open(full_env, "rb") as f:
            enveloped_data_der = f.read()

        # return build_scep_response(enveloped_data_der, nonce_bytes, trans_id_str)
        return build_scep_response(enveloped_data_der, raw_nonce_obj, raw_trans_id_obj)

    except subprocess.CalledProcessError as e:
        print(f"OpenSSL Error: {e.stderr.decode()}")
        return "Internal Error", 500
    except Exception:
        traceback.print_exc()
        return "Error", 500
    # finally:
    #     for fname in [
    #         req_file,
    #         env_file,
    #         inner_file,
    #         csr_file,
    #         dev_crt,
    #         dev_der,
    #         full_env,
    #     ]:
    #         if os.path.exists(fname):
    #             os.remove(fname)


@app.route("/scep/", methods=["GET", "POST"])
def scep():
    op = request.args.get("operation")

    if op == "PKIOperation":
        pki_data = (
            request.data
            if request.method == "POST"
            else base64.b64decode(request.args.get("message"))
        )

        response_data = handle_pki_operation(pki_data)

        if isinstance(response_data, tuple):
            return response_data  # Flask error tuple (message, status_code)

        # resp_filename = f"resp_{os.getpid()}.der"
        resp_filename = f"resp_0.der"
        with open(resp_filename, "wb") as f:
            f.write(response_data)
        print(f"Final SCEP response saved to {resp_filename}")

        return Response(response_data, mimetype="application/x-pki-message")

    return "Forbidden", 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
