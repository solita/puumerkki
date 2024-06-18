#!/usr/bin/env bash

set -eu

declare -a certificates=("https://dvv.fineid.fi/api/v1/cas/111/certificate"
                         "https://dvv.fineid.fi/api/v1/cas/112/certificate"
                         "https://dvv.fineid.fi/api/v1/cas/103/certificate"
                         "https://dvv.fineid.fi/api/v1/cas/102/certificate")
rm citizen-certificate-roots.pem || true

for i in "${certificates[@]}"
do
   curl -s "$i" | openssl x509 -outform PEM >> citizen-certificate-roots.pem
done
