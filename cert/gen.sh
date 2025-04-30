#!/bin/sh

set -e

for M in ca reject; do
	openssl genpkey -algorithm RSA -out cert/$M.key
	openssl x509 -new -key cert/$M.key -out cert/$M.pem -subj /O=tll-tls/OU=test/CN=$M -days 3650 -extfile /etc/ssl/openssl.cnf -extensions v3_ca
done


for M in client server; do
	openssl genpkey -algorithm RSA -out cert/$M.key
	openssl x509 -new -CA cert/ca.pem -CAkey cert/ca.key -force_pubkey cert/$M.key -out cert/$M.pem -subj /O=tll-tls/OU=test/CN=$M -days 3650
done
