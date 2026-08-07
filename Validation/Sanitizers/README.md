# Unsafe sanitizer validation

`run-unsafe-sanitizers.sh` runs `SSLCoreTests`, `SSLCryptoTests`, and
`SSLDTLSTests` through `xcodebuild test` in three isolated
configurations:

- Address Sanitizer;
- Thread Sanitizer;
- Undefined Behavior Sanitizer.

Each configuration uses its own Derived Data directory and result bundle. The
runner pins the Swift compiler, executes the static synchronous-deinit guard,
uses the repository's process-group timeout helper, and rejects newly orphaned
`swiftpm-testing-helper` processes. Test execution is serial and build-task
parallelism is bounded to two jobs.

Cold sanitizer builds on the pinned development toolchain can exceed 30 seconds,
so the default outer timeout is the permitted 120-second maximum. A narrower
limit can be selected when the build cache is warm.

Run every sanitizer:

```sh
Validation/Sanitizers/run-unsafe-sanitizers.sh
```

Run one sanitizer with a shorter timeout:

```sh
Validation/Sanitizers/run-unsafe-sanitizers.sh --sanitizer asan --timeout 60
```

Logs, result bundles, summaries, and failure diagnostics are written under
`.test-artifacts/sanitizers/`. Sanitizer validation remains separate from the
normal package test command.
