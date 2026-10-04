import Foundation

/// This deployment's relay. Not in git: bootstrap.sh copies this template to
/// Calculon/App/RelayEndpoint.swift; fill in your server there.
enum RelayEndpoint {
    /// HTTPS address of your relay (server/README.md). Plain HTTP only works
    /// for hosts on the local network.
    static let url = URL(string: "https://relay.example.com")!
    /// Base64 SHA-256 of a SubjectPublicKeyInfo in the server's certificate
    /// chain; connections whose chain contains none of them are refused.
    /// With the Docker deployment (Caddy + Let's Encrypt) pin Let's Encrypt's
    /// roots, since Caddy gets a new key on every renewal. Empty = no pinning.
    static let spkiPins = [
        "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=", // ISRG Root X1
        "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=", // ISRG Root X2
    ]
}
