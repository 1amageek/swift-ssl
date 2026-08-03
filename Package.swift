// swift-tools-version: 6.2

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
  .enableExperimentalFeature("BuiltinModule")
]

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
    name: "swift-ssl-quic-crypto-stream-validation",
    targets: ["SSLQUICCryptoStreamValidation"]
  ),
  .executable(
    name: "swift-ssl-nist-verification-validation",
    targets: ["SSLNISTVerificationValidation"]
  ),
]

var targets: [Target] = [
  .target(
    name: "SSLCore",
    swiftSettings: ownershipSettings + [
      .enableExperimentalFeature("Volatile")
    ]
  ),
  .target(
    name: "SSLCrypto",
    dependencies: ["SSLCore"],
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
    dependencies: ["SSLCore", "SSLCrypto", "SSLASN1", "SSLX509"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSLQUIC",
    dependencies: ["SSLCore", "SSLCrypto", "SSLTLS"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SSL",
    dependencies: [
      "SSLCore",
      "SSLCrypto",
      "SSLASN1",
      "SSLX509",
      "SSLTLS",
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
    name: "SSLQUICCryptoStreamValidation",
    dependencies: [
      "SSLCore", "SSLCrypto", "SSLQUIC", "SSLTLS",
      "SSLX509",
    ],
    path: "Validation/Targets/QUICCryptoStreamValidation",
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
    .macOS(.v15),
    .iOS(.v18),
    .tvOS(.v18),
    .watchOS(.v11),
    .visionOS(.v2),
  ],
  products: products,
  targets: targets
)
