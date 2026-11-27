// iOS — URLSession uses HTTP/3 when the server supports it.
var request = URLRequest(url: URL(
    string: "https://api.murmur.example/v1/health")!)
// try QUIC immediately instead of discovering it first
request.assumesHTTP3Capable = true

// URLSessionTaskDelegate:
func urlSession(_ session: URLSession, task: URLSessionTask,
                didFinishCollecting metrics: URLSessionTaskMetrics) {
    for t in metrics.transactionMetrics {
        // "h3", "h2", or "http/1.1"
        print("protocol:", t.networkProtocolName ?? "?")
    }
}
