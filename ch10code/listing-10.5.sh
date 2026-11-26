go run -tags serve . \
  -issuer http://localhost:8080/realms/murmur \
  -jwks   http://localhost:8080/realms/murmur/protocol/openid-connect/certs \
  -aud    https://api.murmur.example \
  -typ    at+jwt          # or: -typ JWT if your Keycloak version labels access tokens "JWT"

ACCESS=$(python3 -c 'import json;print(json.load(open("tokens.json"))["access_token"])')
curl -s -H "Authorization: Bearer $ACCESS" -X POST http://127.0.0.1:9000/v1/messages
# accepted: sub=… client_id=murmur-ios scope="openid messages:send contacts:read"
