// TokenRefresher.swift — single-flight refresh with an actor.
struct Tokens: Codable, Equatable { let accessToken: String;
    let refreshToken: String }
protocol TokenStore { func load() throws -> Tokens?;
    func save(_ t: Tokens) throws; func clear() }
protocol AuthAPI { func refresh(_ refreshToken: String) async throws -> Tokens }

actor TokenRefresher {
    private let api: AuthAPI
    private let store: TokenStore
    private var inflight: Task<Tokens, Error>?
    init(api: AuthAPI, store: TokenStore) { self.api = api; self.store = store }

    /// Returns valid tokens after `failedAccessToken` received a 401.
    func refresh(after failedAccessToken: String) async throws -> Tokens {
        guard let current = try store.load() else { throw URLError(
            .userAuthenticationRequired) }
        // already refreshed
        if current.accessToken != failedAccessToken { return current }
        // join the refresh in flight
        if let task = inflight { return try await task.value }

        let task = Task { [api, store] () throws -> Tokens in
            do {
                let fresh = try await api.refresh(current.refreshToken)
                // persist rotation FIRST
                try store.save(fresh)
                return fresh
            } catch {
                // invalid_grant → sign out
                store.clear()
                throw error
            }
        }
        inflight = task
        defer { inflight = nil }
        return try await task.value
    }
}
