// swift-tools-version: 6.4

import Foundation
import PackageDescription

let ownershipSettings: [SwiftSetting] = [
  .enableExperimentalFeature("NonescapableTypes"),
  .enableExperimentalFeature("LifetimeDependence"),
  .enableExperimentalFeature("InoutLifetimeDependence"),
  .enableExperimentalFeature("LifetimeDependenceMutableAccessors"),
  .enableExperimentalFeature("Lifetimes"),
  .enableExperimentalFeature("Extern"),
]

let cryptoSettings = ownershipSettings + [
  .enableExperimentalFeature("BuiltinModule"),
  .enableExperimentalFeature("Volatile"),
]

let tlsTypesDependency: Target.Dependency = .product(
  name: "TLSTypes",
  package: "swift-tls-types"
)

var nistValidationSettings = ownershipSettings
switch ProcessInfo.processInfo.environment["SWIFT_SSL_NIST_VALIDATION_CASE"] {
case nil, "all":
  break
case "p256":
  nistValidationSettings.append(.define("SWIFT_SSL_NIST_P256"))
case "p384-valid":
  nistValidationSettings.append(.define("SWIFT_SSL_NIST_P384_VALID"))
case "p384-mutated":
  nistValidationSettings.append(.define("SWIFT_SSL_NIST_P384_MUTATED"))
case "p521-valid":
  nistValidationSettings.append(.define("SWIFT_SSL_NIST_P521_VALID"))
case "p521-mutated":
  nistValidationSettings.append(.define("SWIFT_SSL_NIST_P521_MUTATED"))
case let invalidSelection?:
  fatalError("Unsupported SWIFT_SSL_NIST_VALIDATION_CASE: \(invalidSelection)")
}

var products: [Product] = [
  .library(name: "SSL", targets: ["SSL"]),
  .library(name: "SSLCore", targets: ["SSLCore"]),
  .library(name: "SSLCrypto", targets: ["SSLCrypto"]),
  .library(name: "SSLASN1", targets: ["SSLASN1"]),
  .library(name: "SSLX509", targets: ["SSLX509"]),
  .library(name: "SSLTLS", targets: ["SSLTLS"]),
  .library(name: "SSLDTLS", targets: ["SSLDTLS"]),
  .library(name: "SSLDTLSMechanism", targets: ["SSLDTLSMechanism"]),
  .library(name: "TLSWire", targets: ["TLSWireCore"]),
  .library(name: "DTLSWire", targets: ["DTLSWireCore"]),
  .library(name: "DTLSHandshake", targets: ["DTLSHandshakeCore"]),
  .library(name: "DTLSRecord", targets: ["DTLSRecordCore"]),
  .library(name: "P2PCoreBytes", targets: ["P2PCoreBytes"]),
  .library(name: "P2PCoreCrypto", targets: ["P2PCoreCrypto"]),
  .library(name: "SSLQUIC", targets: ["SSLQUIC"]),
  .executable(
    name: "swift-ssl-target-validation",
    targets: ["SSLTargetValidation"]
  ),
  .executable(
    name: "swift-ssl-hybrid-target-validation",
    targets: ["SSLHybridTargetValidation"]
  ),
  .executable(
    name: "swift-ssl-facade-validation",
    targets: ["SSLFacadeValidation"]
  ),
  .executable(
    name: "swift-ssl-nist-verification-validation",
    targets: ["SSLNISTVerificationValidation"]
  ),
]

var targets: [Target] = [
  // Shared byte/crypto capability contracts are hosted by swift-ssl so the
  // DTLS mechanism and P2P adapters have one module identity and no package
  // dependency cycle.
  .target(
    name: "P2PCoreBytes",
    path: "Sources/P2PCoreBytes",
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "P2PCoreCrypto",
    dependencies: ["P2PCoreBytes"],
    path: "Sources/P2PCoreCrypto",
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "TLSWireCore",
    dependencies: ["P2PCoreBytes"],
    path: "Sources/TLSWireCore",
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "DTLSWireCore",
    dependencies: ["P2PCoreBytes", "TLSWireCore"],
    path: "Sources/DTLSWireCore",
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "DTLSHandshakeCore",
    dependencies: ["P2PCoreBytes", "P2PCoreCrypto", "TLSWireCore", "DTLSWireCore"],
    path: "Sources/DTLSHandshakeCore",
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "DTLSRecordCore",
    dependencies: ["P2PCoreBytes", "P2PCoreCrypto"],
    path: "Sources/DTLSRecordCore",
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSLDTLSMechanism",
    dependencies: [
      "P2PCoreBytes", "P2PCoreCrypto", "TLSWireCore", "DTLSWireCore",
      "DTLSHandshakeCore", "DTLSRecordCore",
    ],
    path: "Sources/DTLSEngineCore",
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSLCore",
    dependencies: [tlsTypesDependency],
    swiftSettings: ownershipSettings + [
      .enableExperimentalFeature("Volatile")
    ]
  ),
  .target(
    name: "SSLCrypto",
    dependencies: ["SSLCore", tlsTypesDependency],
    swiftSettings: cryptoSettings
  ),
  .target(
    name: "SSLASN1",
    dependencies: ["SSLCore"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSLX509",
    dependencies: ["SSLCore", "SSLCrypto", "SSLASN1"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSLTLS",
    dependencies: [tlsTypesDependency, "SSLCore", "SSLCrypto", "SSLASN1", "SSLX509"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSLDTLS",
    dependencies: ["SSLCore", "SSLCrypto", "SSLDTLSMechanism"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSLQUIC",
    dependencies: [tlsTypesDependency, "SSLCore", "SSLCrypto", "SSLTLS"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSL",
    dependencies: [
      "SSLCore",
      tlsTypesDependency,
      "SSLCrypto",
      "SSLASN1",
      "SSLX509",
      "SSLTLS",
      "SSLDTLS",
      "SSLQUIC",
    ],
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SSLTargetValidation",
    dependencies: [
      "SSL",
      "SSLCore",
      "SSLCrypto",
      "SSLASN1",
      "SSLX509",
      "SSLTLS",
      "SSLQUIC",
    ],
    path: "Validation/Targets/TargetValidation",
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SSLHybridTargetValidation",
    dependencies: [
      "SSLCore",
      "SSLCrypto",
      "SSLTLS",
    ],
    path: "Validation/Targets/HybridTargetValidation",
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SSLFacadeValidation",
    dependencies: ["SSL"],
    path: "Validation/Targets/FacadeValidation",
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SSLNISTVerificationValidation",
    dependencies: [
      "SSLCore",
      "SSLCrypto",
    ],
    path: "Validation/Targets/NISTVerificationValidation",
    swiftSettings: nistValidationSettings
  ),
  .testTarget(
    name: "SSLCoreTests",
    dependencies: ["SSLCore"],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SSLCryptoTests",
    dependencies: ["SSLCore", "SSLCrypto"],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SSLX509Tests",
    dependencies: [
      "SSLCore", "SSLCrypto", "SSLASN1", "SSLX509",
    ],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SSLASN1Tests",
    dependencies: ["SSLCore", "SSLASN1"],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SSLTLSModelTests",
    dependencies: [
      "SSLCore", "SSLCrypto", "SSLX509", "SSLTLS", "SSLQUIC",
    ],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SSLDTLSTests",
    dependencies: ["SSLCore", "SSLDTLS"],
    swiftSettings: ownershipSettings
  ),
]

if ProcessInfo.processInfo.environment["SWIFT_SSL_ENABLE_ECH_INTEROP_VALIDATION"] == "1" {
  products.append(
    .executable(
      name: "swift-ssl-ech-interop-validation",
      targets: ["SSLECHInteropValidation"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SSLECHInteropValidation",
      dependencies: ["SSLCore", "SSLCrypto", "SSLTLS"],
      path: "Validation/Targets/ECHInteropValidation",
      swiftSettings: ownershipSettings
    )
  )
}

if ProcessInfo.processInfo.environment["SWIFT_SSL_ENABLE_BENCHMARKS"] == "1" {
  products.append(
    .executable(
      name: "swift-ssl-sha256-benchmark",
      targets: ["SSLSHA256Benchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SSLSHA256Benchmark",
      dependencies: ["SSLCore", "SSLCrypto"],
      path: "Benchmarks/SHA256/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-mlkem-benchmark",
      targets: ["SSLMLKEMBenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SSLMLKEMBenchmark",
      dependencies: ["SSL"],
      path: "Benchmarks/MLKEM/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-tls-hybrid-benchmark",
      targets: ["SSLTLSHybridBenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SSLTLSHybridBenchmark",
      dependencies: ["SSLCore", "SSLCrypto", "SSLTLS"],
      path: "Benchmarks/TLSHybrid/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-tls-session-benchmark",
      targets: ["SSLTLSSessionBenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SSLTLSSessionBenchmark",
      dependencies: ["SSLCore", "SSLCrypto", "SSLTLS", "SSLX509"],
      path: "Benchmarks/TLSSession/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-mldsa-benchmark",
      targets: ["SSLMLDSABenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SSLMLDSABenchmark",
      dependencies: ["SSL"],
      path: "Benchmarks/MLDSA/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-hpke-benchmark",
      targets: ["SSLHPKEBenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SSLHPKEBenchmark",
      dependencies: ["SSLCore", "SSLCrypto"],
      path: "Benchmarks/HPKE/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
}

let package = Package(
  name: "swift-ssl",
  platforms: [
    .macOS(.v26),
    .iOS(.v26),
    .tvOS(.v26),
    .watchOS(.v26),
    .visionOS(.v26),
  ],
  products: products,
  dependencies: [
    .package(
      url: "https://github.com/1amageek/swift-tls-types.git",
      from: "0.1.0"
    ),
  ],
  targets: targets
)
