#!/bin/sh

set -x

openssl ecparam -name prime256v1 -genkey -noout -out priv.pem
openssl ec -in priv.pem -noout -text
openssl ec -in priv.pem -pubout -out pub.pem

publicKey=$(cat pub.pem | awk '{printf "%s\\n", $0}')
keyJson=$(printf "{\"publicKey\": %s, \"scheme\": 0}" "\"${publicKey}\"")

