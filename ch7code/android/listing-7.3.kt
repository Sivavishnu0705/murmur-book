// Android — Cronet (or android.net.http.HttpEngine on recent Android versions).
// OkHttp does not speak HTTP/3; Murmur uses Cronet where QUIC matters.
val engine = CronetEngine.Builder(context)
    .enableQuic(true)
    // fallback when UDP is blocked
    .enableHttp2(true)
    // skip waiting for Alt-Svc discovery
    .addQuicHint("api.murmur.example", 443, 443)
    .build()

// In UrlRequest.Callback.onSucceeded(request, info):
// info.negotiatedProtocol → "h3" (HTTP/3 over QUIC) or "h2" (HTTP/2 over
// TLS/TCP) Log it in debug builds; alert in tests if h3 silently stops being
// negotiated.
