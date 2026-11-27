import Foundation

let config = URLSessionConfiguration.default
config.tlsMinimumSupportedProtocolVersion = .TLSv13        // iOS 13+
let murmurSession = URLSession(configuration: config)

// Check the negotiated version from task metrics (debug builds / tests):
final class TLSMetricsDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    didFinishCollecting metrics: URLSessionTaskMetrics) {
        for t in metrics.transactionMetrics {
            assert(t.negotiatedTLSProtocolVersion == .TLSv13,
                   "expected TLS 1.3, got " +
                   "\(String(describing: t.negotiatedTLSProtocolVersion))")
        }
    }
}
