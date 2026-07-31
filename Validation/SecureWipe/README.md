# Secure wipe code-generation validation

`verify-codegen.sh` compiles the production `SwiftSSLCore` and `SwiftSSLCrypto` sources for Native, WASI, and Embedded WASI at `-O` and `-Osize`. It fails unless generated LLVM IR retains the production volatile byte store and the exact cleanup/control-flow contracts.

The Core gate checks whole-module output on every target and supported per-file output for `SecretBytes` and `SecureWipe`. It uses CFG path tracking for initializer failure cleanup, explicit destruction, and value-witness cleanup; a textual wipe-before-free ordering is not sufficient.

The Crypto gate verifies that HMAC-SHA-256:

- wipes the inner and outer SHA-256 state and pending blocks at addresses derived from the stable storage object before deallocation;
- follows an out-of-line wipe helper when `-Osize` splits the deinitializer;
- wipes the normalized key state, key block, inner digest, and calculated verification tag on success and failure paths;
- binds finalization, calculated-tag provenance, and constant-time equal-length tag comparison to the success return; optimized inline comparisons are checked as reduction loops;
- performs no allocation, reference-count operation, or HMAC-layer input copy in `update`.

For HKDF-SHA-256 expand, the same gate verifies that:

- the HMAC key schedule is prepared once and working contexts are kept inline without heap or reference-count operations;
- prepared and working SHA-256 contexts, inner digests, and the partial-block scratch are erased on generated exit paths;
- complete HMAC blocks are finalized directly into caller output;
- only a partial final block uses the fixed 32-byte scratch before copying its requested prefix into caller output; the actual copy length must be dominated by the exact `0 <= count < 32` guards.

Run the complete matrix:

```sh
Validation/SecureWipe/verify-codegen.sh
```

Run one bounded configuration:

```sh
SWIFT_SSL_CODEGEN_TARGET=embedded-wasi \
SWIFT_SSL_CODEGEN_OPTIMIZATION=-Osize \
Validation/SecureWipe/verify-codegen.sh
```

Runtime ownership, range validity, exactly-once deallocation, and concurrency remain covered by separate tests and sanitizer programs.
