import Network

let tls = NWProtocolTLS.Options()
sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
let params = NWParameters(tls: tls)
let connection = NWConnection(host: "api.murmur.example", port: 443, using: params)
