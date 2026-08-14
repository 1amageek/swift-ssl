@_exported import NetworkingCore
@_exported import NetworkingTime
@_exported import SSLCryptoContracts

/// The wall-clock instant used for certificate and credential verification.
public typealias VerificationInstant = NetworkingTime.UnixInstant

/// Clock failures are defined by the shared networking time substrate.
public typealias ClockError = NetworkingTime.TimeError
