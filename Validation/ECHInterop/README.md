# ECH interoperability validation

This validation is intentionally separate from the normal unit-test suite. It
executes both RFC 9849 directions against pinned BoringSSL commit
`ae49d2681a56ca7b8609f6039a770fda2a8eb550`:

- BoringSSL client to the Pure Swift ECH opener.
- Pure Swift ECH sealer to the BoringSSL server.

The BoringSSL server reaches its real certificate-selection callback only
after ECH trial decryption and ClientHelloInner reconstruction. The validation
requires `SSL_ech_accepted` and the origin SNI at that boundary.

Use `run-interop.sh BORINGSSL_SOURCE`. The script keeps all build products
under `.build/validation-ech-interop` and never runs as part of `xcodebuild
test`.
