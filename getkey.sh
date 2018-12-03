#!/bin/sh

set -x

openssl ecparam -name prime256v1 -genkey -noout -out priv.pem
openssl ec -in priv.pem -pubout -out pub.pem

address=localhost
publicKey=$(cat pub.pem | awk '{printf "%s\\n", $0}')
keyJson=$(printf "{\"publicKey\": %s, \"scheme\": 0}" "\"${publicKey}\"")

printf "\n\nGet Button Info\n\n"

curl -v -H "Content-Type: application/json" \
--request GET \
${address}

printf "\n\nPost Self Public Key\n\n"

curl -v -H "Content-Type: application/json" \
--request POST \
--data "${keyJson}" \
${address}/pubkey

printf "\n\nGet Button Public Key\n\n"

curl -v -H "Content-Type: application/json" \
--request GET \
${address}/pubkey

