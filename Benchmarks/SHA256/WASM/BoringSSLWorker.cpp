#include <openssl/crypto.h>
#include <openssl/sha2.h>

#include <wasi/api.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace {

constexpr size_t kDigestByteCount = SHA256_DIGEST_LENGTH;

bool parse_integer(const char *text, bool allow_zero, size_t *value) {
  if (text == nullptr || text[0] == '\0' || text[0] == '-') {
    return false;
  }

  errno = 0;
  char *end = nullptr;
  const unsigned long long parsed = std::strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' ||
      parsed > std::numeric_limits<size_t>::max() ||
      (!allow_zero && parsed == 0)) {
    return false;
  }

  *value = static_cast<size_t>(parsed);
  return true;
}

uint8_t *make_input(size_t byte_count, size_t input_offset) {
  if (input_offset > std::numeric_limits<size_t>::max() - byte_count) {
    return nullptr;
  }

  uint8_t *input =
      static_cast<uint8_t *>(std::malloc(input_offset + byte_count));
  if (input == nullptr) {
    return nullptr;
  }

  std::memset(input, 0xa5, input_offset);
  for (size_t index = 0; index < byte_count; ++index) {
    input[input_offset + index] = static_cast<uint8_t>(index * 31 + 17);
  }
  return input;
}

bool monotonic_nanoseconds(uint64_t *value) {
  __wasi_timestamp_t timestamp = 0;
  const __wasi_errno_t error = __wasi_clock_time_get(
      __WASI_CLOCKID_MONOTONIC, 1, &timestamp);
  if (error != 0) {
    return false;
  }
  *value = static_cast<uint64_t>(timestamp);
  return true;
}

bool hash_iterations(uint8_t *input, size_t byte_count, size_t input_offset,
                     uint8_t *output, size_t iterations, uint64_t *checksum) {
  uint64_t accumulated = 0;
  for (size_t iteration = 0; iteration < iterations; ++iteration) {
    input[input_offset] = static_cast<uint8_t>(iteration);
    if (SHA256(input + input_offset, byte_count, output) == nullptr) {
      return false;
    }
    accumulated += output[iteration & 31];
  }
  *checksum = accumulated;
  return true;
}

void print_hex(const uint8_t *bytes, size_t byte_count) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  for (size_t index = 0; index < byte_count; ++index) {
    std::putchar(kHexDigits[bytes[index] >> 4]);
    std::putchar(kHexDigits[bytes[index] & 0x0f]);
  }
}

int validate(size_t byte_count, size_t iterations, size_t input_offset) {
  uint8_t *input = make_input(byte_count, input_offset);
  if (input == nullptr) {
    std::fputs("input allocation failed\n", stderr);
    return 2;
  }

  uint8_t output[kDigestByteCount] = {};
  for (size_t iteration = 0; iteration < iterations; ++iteration) {
    input[input_offset] = static_cast<uint8_t>(iteration);
    if (SHA256(input + input_offset, byte_count, output) == nullptr) {
      std::free(input);
      std::fputs("BoringSSL SHA-256 failed\n", stderr);
      return 2;
    }
    std::printf("DIGEST,%zu,", iteration);
    print_hex(output, kDigestByteCount);
    std::putchar('\n');
  }

  std::free(input);
  return 0;
}

int benchmark(size_t byte_count, size_t iterations,
              size_t warmup_iterations, size_t input_offset) {
  uint8_t *warmup_input = make_input(byte_count, input_offset);
  uint8_t *input = make_input(byte_count, input_offset);
  if (warmup_input == nullptr || input == nullptr) {
    std::free(warmup_input);
    std::free(input);
    std::fputs("input allocation failed\n", stderr);
    return 2;
  }

  uint8_t warmup_output[kDigestByteCount] = {};
  uint8_t output[kDigestByteCount] = {};
  uint64_t warmup_checksum = 0;
  if (!hash_iterations(warmup_input, byte_count, input_offset, warmup_output,
                       warmup_iterations, &warmup_checksum)) {
    std::free(warmup_input);
    std::free(input);
    std::fputs("BoringSSL SHA-256 warmup failed\n", stderr);
    return 2;
  }

  uint64_t start = 0;
  uint64_t end = 0;
  uint64_t checksum = 0;
  if (!monotonic_nanoseconds(&start) ||
      !hash_iterations(input, byte_count, input_offset, output, iterations,
                       &checksum) ||
      !monotonic_nanoseconds(&end) || end < start) {
    std::free(warmup_input);
    std::free(input);
    std::fputs("BoringSSL SHA-256 timing failed\n", stderr);
    return 2;
  }

  std::printf("RESULT,%" PRIu64 ",%" PRIu64 ",", end - start, checksum);
  print_hex(output, kDigestByteCount);
  std::putchar('\n');

  std::free(warmup_input);
  std::free(input);
  return 0;
}

void print_usage() {
  std::fputs(
      "usage: boringssl-sha256-wasm-benchmark <bytes> <iterations> "
      "<warmup-iterations> [input-offset]\n"
      "       boringssl-sha256-wasm-benchmark --validate <bytes> "
      "<iterations> [input-offset]\n"
      "       boringssl-sha256-wasm-benchmark --capabilities\n",
      stderr);
}

}  // namespace

int main(int argc, char **argv) {
  if (argc == 2 && std::strcmp(argv[1], "--capabilities") == 0) {
    const int assembly_enabled = CRYPTO_has_asm();
    std::printf("CAPABILITY,boringssl_asm,%d\n", assembly_enabled);
    return assembly_enabled == 0 ? 0 : 2;
  }

  if ((argc == 4 || argc == 5) &&
      std::strcmp(argv[1], "--validate") == 0) {
    size_t byte_count = 0;
    size_t iterations = 0;
    size_t input_offset = 0;
    if (!parse_integer(argv[2], false, &byte_count) ||
        !parse_integer(argv[3], false, &iterations) ||
        (argc == 5 && !parse_integer(argv[4], true, &input_offset)) ||
        input_offset > std::numeric_limits<size_t>::max() - byte_count) {
      print_usage();
      return 2;
    }
    return validate(byte_count, iterations, input_offset);
  }

  if (argc != 4 && argc != 5) {
    print_usage();
    return 2;
  }

  size_t byte_count = 0;
  size_t iterations = 0;
  size_t warmup_iterations = 0;
  size_t input_offset = 0;
  if (!parse_integer(argv[1], false, &byte_count) ||
      !parse_integer(argv[2], false, &iterations) ||
      !parse_integer(argv[3], true, &warmup_iterations) ||
      (argc == 5 && !parse_integer(argv[4], true, &input_offset)) ||
      input_offset > std::numeric_limits<size_t>::max() - byte_count) {
    print_usage();
    return 2;
  }

  return benchmark(
      byte_count, iterations, warmup_iterations, input_offset);
}
