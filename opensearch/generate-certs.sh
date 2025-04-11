#!/bin/bash

mkdir -p demo-certificates

# Generate CA key and cert
openssl genrsa -out demo-certificates/root-ca.key 2048
openssl req -x509 -new -nodes -key demo-certificates/root-ca.key -sha256 -days 3650 -out demo-certificates/root-ca.pem -subj "/C=US/ST=Dev/L=Local/O=Example/OU=IT/CN=root-ca"

# Generate OpenSearch node cert
openssl genrsa -out demo-certificates/node.key 2048
openssl req -new -key demo-certificates/node.key -out demo-certificates/node.csr -subj "/C=US/ST=Dev/L=Local/O=Example/OU=IT/CN=webamon-node1"

openssl x509 -req -in demo-certificates/node.csr -CA demo-certificates/root-ca.pem -CAkey demo-certificates/root-ca.key -CAcreateserial -out demo-certificates/node.pem -days 365 -sha256

# Cleanup
rm demo-certificates/node.csr
rm demo-certificates/root-ca.srl

echo "Demo certs created in ./demo-certificates"
