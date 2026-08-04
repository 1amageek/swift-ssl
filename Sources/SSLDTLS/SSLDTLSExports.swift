// The public SSLDTLS module is the single import surface for the DTLS 1.2
// profile, record protection, and sans-IO handshake mechanism. The mechanism
// target is kept separate internally so its large state machine does not force
// the primitive files to share implementation details.
@_exported import SSLDTLSMechanism
@_exported import DTLSWireCore
@_exported import DTLSHandshakeCore
@_exported import DTLSRecordCore
