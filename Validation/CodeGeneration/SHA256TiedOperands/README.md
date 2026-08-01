# SHA-256 ARM64 tied-operand code-generation probe

This manual validation captures the compiler boundary behind the ARM64
SHA-256 throughput gap. It is separate from unit tests and benchmarks.

Run it with the pinned Swift toolchain:

```sh
Validation/CodeGeneration/SHA256TiedOperands/capture-current-codegen.sh
```

Both the Swift and Clang intrinsic forms currently lower a four-round pair by
copying a live input into the destructive destination before `sha256h` or
`sha256h2`. BoringSSL's pinned hand-written assembly instead copies the old
state to a temporary, overwrites both state registers directly, and uses the
temporary as the second hash instruction's input.

The script intentionally fails if the copy shape disappears. That outcome is
not a regression: it means the pinned toolchain changed and the production
kernel and formal benchmark must be reevaluated.
