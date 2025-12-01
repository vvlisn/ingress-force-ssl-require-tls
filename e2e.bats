#!/usr/bin/env bats

@test "reject when force-ssl-redirect is true without TLS" {
  run kwctl run annotated-policy.wasm -r test_data/ingress-force-ssl-no-tls.json --settings-json '{"validate_force_ssl_redirect": true}'

  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
}

@test "accept when force-ssl-redirect is true with matching TLS hosts" {
  run kwctl run annotated-policy.wasm -r test_data/ingress-force-ssl-with-tls.json --settings-json '{"validate_force_ssl_redirect": true}'

  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
