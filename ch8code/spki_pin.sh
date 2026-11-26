#!/usr/bin/env bash
# Listing 8.4 (Bash) — SPKI SHA-256 pin of the FIRST certificate in a PEM file, with OpenSSL.
# Usage: ./spki_pin.sh cert.pem
openssl x509 -in "$1" -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
