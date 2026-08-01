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
  .library(name: "SwiftSSL", targets: ["SwiftSSL"]),
  .library(name: "SwiftSSLCore", targets: ["SwiftSSLCore"]),
  .library(name: "SwiftSSLCrypto", targets: ["SwiftSSLCrypto"]),
  .library(name: "SwiftSSLASN1", targets: ["SwiftSSLASN1"]),
  .library(name: "SwiftSSLX509", targets: ["SwiftSSLX509"]),
  .library(name: "SwiftSSLTLS", targets: ["SwiftSSLTLS"]),
  .library(name: "SwiftSSLQUIC", targets: ["SwiftSSLQUIC"]),
  .executable(
    name: "swift-ssl-target-validation",
    targets: ["SwiftSSLTargetValidation"]
  ),
  .executable(
    name: "swift-ssl-hybrid-target-validation",
    targets: ["SwiftSSLHybridTargetValidation"]
  ),
  .executable(
    name: "swift-ssl-facade-validation",
    targets: ["SwiftSSLFacadeValidation"]
  ),
  .executable(
    name: "swift-ssl-quic-crypto-stream-validation",
    targets: ["SwiftSSLQUICCryptoStreamValidation"]
  ),
  .executable(
    name: "swift-ssl-nist-verification-validation",
    targets: ["SwiftSSLNISTVerificationValidation"]
  ),
  .executable(
    name: "swift-ssl-ech-interop-validation",
    targets: ["SwiftSSLECHInteropValidation"]
  ),
]

var targets: [Target] = [
  .target(
    name: "SwiftSSLCore",
    swiftSettings: ownershipSettings + [
      .enableExperimentalFeature("Volatile")
    ]
  ),
  .target(
    name: "SwiftSSLCrypto",
    dependencies: ["SwiftSSLCore"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SwiftSSLASN1",
    dependencies: ["SwiftSSLCore"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SwiftSSLX509",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLASN1"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SwiftSSLTLS",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLX509"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SwiftSSLQUIC",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLTLS"],
    swiftSettings: ownershipSettings
  ),
  .target(
    name: "SwiftSSL",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto"],
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SwiftSSLTargetValidation",
    dependencies: [
      "SwiftSSL",
      "SwiftSSLCore",
      "SwiftSSLCrypto",
      "SwiftSSLASN1",
      "SwiftSSLTLS",
      "SwiftSSLQUIC",
    ],
    path: "Validation/Targets/TargetValidation",
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SwiftSSLHybridTargetValidation",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLTLS"],
    path: "Validation/Targets/HybridTargetValidation",
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SwiftSSLFacadeValidation",
    dependencies: ["SwiftSSL"],
    path: "Validation/Targets/FacadeValidation",
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SwiftSSLQUICCryptoStreamValidation",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLQUIC", "SwiftSSLTLS"],
    path: "Validation/Targets/QUICCryptoStreamValidation",
    swiftSettings: ownershipSettings
  ),
  .executableTarget(
    name: "SwiftSSLNISTVerificationValidation",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto"],
    path: "Validation/Targets/NISTVerificationValidation",
    swiftSettings: nistValidationSettings
  ),
  .executableTarget(
    name: "SwiftSSLECHInteropValidation",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLTLS"],
    path: "Validation/Targets/ECHInteropValidation",
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SwiftSSLCoreTests",
    dependencies: ["SwiftSSLCore"],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SwiftSSLCryptoTests",
    dependencies: ["SwiftSSLCore", "SwiftSSLCrypto"],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SwiftSSLX509Tests",
    dependencies: ["SwiftSSLCore", "SwiftSSLASN1", "SwiftSSLX509"],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SwiftSSLASN1Tests",
    dependencies: ["SwiftSSLCore", "SwiftSSLASN1"],
    swiftSettings: ownershipSettings
  ),
  .testTarget(
    name: "SwiftSSLTLSModelTests",
    dependencies: [
      "SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLX509", "SwiftSSLTLS", "SwiftSSLQUIC",
    ],
    swiftSettings: ownershipSettings
  ),
]

if ProcessInfo.processInfo.environment["SWIFT_SSL_ENABLE_BENCHMARKS"] == "1" {
  products.append(
    .executable(
      name: "swift-ssl-sha256-benchmark",
      targets: ["SwiftSSLSHA256Benchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SwiftSSLSHA256Benchmark",
      dependencies: ["SwiftSSLCore", "SwiftSSLCrypto"],
      path: "Benchmarks/SHA256/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-mlkem-benchmark",
      targets: ["SwiftSSLMLKEMBenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SwiftSSLMLKEMBenchmark",
      dependencies: ["SwiftSSL"],
      path: "Benchmarks/MLKEM/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-tls-hybrid-benchmark",
      targets: ["SwiftSSLTLSHybridBenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SwiftSSLTLSHybridBenchmark",
      dependencies: ["SwiftSSLCore", "SwiftSSLCrypto", "SwiftSSLTLS"],
      path: "Benchmarks/TLSHybrid/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-mldsa-benchmark",
      targets: ["SwiftSSLMLDSABenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SwiftSSLMLDSABenchmark",
      dependencies: ["SwiftSSL"],
      path: "Benchmarks/MLDSA/SwiftWorker",
      swiftSettings: ownershipSettings
    )
  )
  products.append(
    .executable(
      name: "swift-ssl-hpke-benchmark",
      targets: ["SwiftSSLHPKEBenchmark"]
    )
  )
  targets.append(
    .executableTarget(
      name: "SwiftSSLHPKEBenchmark",
      dependencies: ["SwiftSSLCore", "SwiftSSLCrypto"],
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
