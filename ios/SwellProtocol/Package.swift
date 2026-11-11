// swift-tools-version:5.9
import PackageDescription

// The Swell Protocol library: the cryptography of Swell's end-to-end encryption and nothing else.
// It has no dependency (CryptoKit only), no storage, no network and no app code. Licence: Apache-2.0 (LICENSE).
// Specification: docs/SWELL-PROTOCOL-SPEC.md. Shared test vectors: docs/protocol-vectors/.
//
// ML-KEM-768 comes from CryptoKit and exists from iOS 26 and macOS 26, which is why those are the minimum (spec 4.1).
let package = Package(
    name: "SwellProtocol",
    platforms: [.iOS("26.0"), .macOS("26.0")],
    products: [.library(name: "SwellProtocol", targets: ["SwellProtocol"])],
    targets: [
        .target(name: "SwellProtocol"),
        .testTarget(name: "SwellProtocolTests", dependencies: ["SwellProtocol"]),
    ]
)
