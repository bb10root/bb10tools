#!/bin/sh

# Root key (RSA 1024)
openssl genrsa -out myRoot.key 1024

# Root certificate (self-signed)
openssl req -x509 -new -nodes -key myRoot.key -sha256 -days 3650 \
    -subj "/C=UA/O=MyCompany/CN=My Root CA" \
    -out myRoot.crt


# Intermediate key (RSA 1024)
openssl genrsa -out myIntermediate.key 1024

openssl req -new -key myIntermediate.key \
    -subj "/C=UA/O=MyCompany/CN=My Intermediate CA" \
    -out myIntermediate.csr

openssl x509 -req -in myIntermediate.csr \
    -CA myRoot.crt -CAkey myRoot.key -CAcreateserial \
    -out myIntermediate.crt -days 1825 -sha256 \
    -extfile intermediate.cnf -extensions v3_ca


# RA key (RSA 1024)
openssl genrsa -out myRA.key 1024

openssl req -new -key myRA.key \
    -subj "/C=UA/O=MyCompany/CN=My RA" \
    -out myRA.csr

openssl x509 -req -in myRA.csr \
    -CA myIntermediate.crt -CAkey myIntermediate.key -CAcreateserial \
    -out myRA.crt -days 1825 -sha256 \
    -extfile ra.cnf -extensions v3_ra


# Verify chain
openssl verify -CAfile myRoot.crt -untrusted myIntermediate.crt myRA.crt

