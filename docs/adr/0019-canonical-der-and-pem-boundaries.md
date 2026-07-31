# ADR 0019: Canonical DER and PEM boundaries

## Status

Accepted. The implementation is introduced incrementally; the remaining key and certificate container formats are separate responsibilities.

## Decision

`SwiftSSLASN1` owns the byte-level format boundary and has no file, socket, Foundation, or platform trust-store dependency.

- `DERCursor` accepts definite-length DER only, enforces parsing budgets, rejects non-minimal tags and lengths, and requires complete consumption at the caller boundary.
- `DERPrimitiveCodec` decodes BOOLEAN, positive INTEGER, OCTET STRING, BIT STRING, and OBJECT IDENTIFIER with canonical-value checks and typed failures.
- `DERWriter` preflights the entire TLV before mutating its bounded `ByteBuilder`, so capacity failure cannot report partial success.
- `PEMCodec` accepts a single RFC 7468 textual block, exact matching labels, LF/CRLF line breaks, strict Base64 alphabet/padding, and a bounded decoded output. It returns an owned DER buffer; it never returns a view into the input text.
- `PEMBlock` owns its DER bytes and exposes them only through a scoped borrow. Labels are validated ASCII values and are not normalized.

The format layer intentionally does not infer algorithm meaning. SPKI, PKCS #8, and X.509 types consume these primitives and apply their own algorithm and policy validation.

## Invariants

```text
caller text owner
    -> scoped Span borrow
        -> strict PEM boundary/Base64 parser
            -> one owned DER buffer
                -> DER cursor + primitive codec
                    -> algorithm-specific container / certificate layer
```

The parser copies only the decoded DER output and the small label value. Every output limit, integer overflow, malformed boundary, non-canonical encoding, and trailing-data condition is a typed failure. No malformed input is converted into an empty or default value.

## Verification

Native `SwiftSSLASN1Tests` cover nested DER, indefinite/non-minimal/truncated encodings, canonical primitive values, OID and bit-string rejection, transactional writer capacity failure, long-form lengths, PEM round trips, CRLF, malformed Base64, label mismatch, output limits, and trailing data. WASI and Embedded-WASI target validation must be rerun after format consumers are added.
