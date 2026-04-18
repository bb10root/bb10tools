#!/bin/sh

# 1. Root CA (Імітація BlackBerry Root)
# Використовуємо криву P-521 та SHA-512
openssl ecparam -name secp521r1 -genkey -noout -out myRoot.key

openssl req -x509 -new -nodes -key myRoot.key -sha512 -days 7300 \
    -subj "/C=CA/O=Research In Motion Limited/OU=BlackBerry/CN=My Root CA" \
    -out myRoot.crt

# 2. Intermediate CA
# Використовуємо криву P-384 та SHA-384
openssl ecparam -name secp384r1 -genkey -noout -out myIntermediate.key

openssl req -new -key myIntermediate.key \
    -subj "/C=CA/O=Research In Motion Limited/OU=BlackBerry/CN=My Intermediate CA" \
    -out myIntermediate.csr

openssl x509 -req -in myIntermediate.csr \
    -CA myRoot.crt -CAkey myRoot.key -CAcreateserial \
    -out myIntermediate.crt -days 3650 -sha384 \
    -extfile intermediate.cnf -extensions v3_ca

# 3. Registration Authority (RA)
# Використовуємо криву P-256 (prime256v1) та SHA-256
openssl ecparam -name prime256v1 -genkey -noout -out myRA.key

openssl req -new -key myRA.key \
    -subj "/C=CA/O=Research In Motion Limited/OU=BlackBerry/CN=My RA" \
    -out myRA.csr

openssl x509 -req -in myRA.csr \
    -CA myIntermediate.crt -CAkey myIntermediate.key -CAcreateserial \
    -out myRA.crt -days 3650 -sha256 \
    -extfile ra.cnf -extensions v3_ra

# Перевірка ланцюжка
echo "Verifying chain..."
openssl verify -CAfile myRoot.crt -untrusted myIntermediate.crt myRA.crt

# Підготовка файлів для сервера та eagent.conf
mkdir -p ../scep-server
cp myRoot.crt ../scep-server/ca.crt
cp myRoot.key ../scep-server/ca.key

echo "Generating eagent.conf..."
{
    echo "#ra_addr"
    echo "http://192.168.1.146/scep/"
    echo "#ra_port"
    echo "8080"
    echo "#rootca_cert"
    cat myRoot.crt
    echo "#subca_cert"
    cat myIntermediate.crt
    echo "#ra_cert"
    cat myRA.crt
    echo "#"
} > eagent.conf

chmod 666 eagent.conf
echo "Done!"
