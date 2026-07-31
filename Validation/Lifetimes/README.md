# Lifetime negative-compilation validation

`verify-negative-compilation.sh` compiles intentionally invalid clients together
with the production `SwiftSSLCore` sources. A fixture passes only when the pinned
compiler rejects it with the expected ownership or lifetime diagnostic.
Every compiler process is bounded by a 30-second process-group timeout.

The validation covers Native, WASI, and Embedded WASI using the same production
ownership features:

- returning a borrowed `Span` from `SecretBytes.withBorrowedBytes`;
- capturing a borrowed `Span` in an unstructured task;
- capturing an initializer `MutableSpan` in an escaping closure;
- consuming one `SecretBytes` owner twice.

Run the validation from any directory with:

```sh
Validation/Lifetimes/verify-negative-compilation.sh
```

The fixtures are deliberately uncompilable and must remain outside package test
targets.
