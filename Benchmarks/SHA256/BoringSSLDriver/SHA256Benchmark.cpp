#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require_assembly_backend() {
  if (CRYPTO_has_asm() != 1) {
    throw std::runtime_error("BoringSSL assembly backend is unavailable");
  }
}

std::vector<uint8_t> make_input(size_t byte_count) {
  std::vector<uint8_t> input;
  input.reserve(byte_count);
  for (size_t index = 0; index < byte_count; ++index) {
    input.push_back(static_cast<uint8_t>(index * 31 + 17));
  }
  return input;
}

uint64_t run(std::vector<uint8_t> &input,
             std::array<uint8_t, SHA256_DIGEST_LENGTH> &output,
             size_t iterations) {
  uint64_t checksum = 0;
  for (size_t iteration = 0; iteration < iterations; ++iteration) {
    input[0] = static_cast<uint8_t>(iteration);
    if (SHA256(input.data(), input.size(), output.data()) == nullptr) {
      throw std::runtime_error("BoringSSL SHA-256 failed");
    }
    checksum += output[iteration & 31];
  }
  return checksum;
}

std::string hex_string(const std::array<uint8_t, SHA256_DIGEST_LENGTH> &bytes) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (uint8_t byte : bytes) {
    stream << std::setw(2) << static_cast<unsigned>(byte);
  }
  return stream.str();
}

size_t parse_positive(const char *value) {
  const std::string text(value);
  size_t parsed_count = 0;
  const unsigned long long parsed = std::stoull(text, &parsed_count, 10);
  if (parsed_count != text.size() || parsed == 0) {
    throw std::invalid_argument("Expected a positive integer");
  }
  return static_cast<size_t>(parsed);
}

void validate(size_t byte_count, size_t iterations) {
  auto input = make_input(byte_count);
  std::array<uint8_t, SHA256_DIGEST_LENGTH> output{};
  for (size_t iteration = 0; iteration < iterations; ++iteration) {
    input[0] = static_cast<uint8_t>(iteration);
    if (SHA256(input.data(), input.size(), output.data()) == nullptr) {
      throw std::runtime_error("BoringSSL SHA-256 failed");
    }
    std::cout << "DIGEST," << iteration << ',' << hex_string(output) << '\n';
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc == 2 && std::string(argv[1]) == "--capabilities") {
    const int assembly_enabled = CRYPTO_has_asm();
    std::cout << "CAPABILITY,boringssl_asm," << assembly_enabled << '\n';
    return assembly_enabled == 1 ? 0 : 2;
  }

  if (argc == 4 && std::string(argv[1]) == "--validate") {
    try {
      require_assembly_backend();
      validate(parse_positive(argv[2]), parse_positive(argv[3]));
      return 0;
    } catch (const std::exception &error) {
      std::cerr << error.what() << '\n';
      return 2;
    }
  }

  if (argc != 4) {
    std::cerr << "usage: boringssl-sha256-benchmark <bytes> <iterations> "
                 "<warmup-iterations>\n"
                 "       boringssl-sha256-benchmark --validate <bytes> "
                 "<iterations>\n";
    return 2;
  }

  try {
    require_assembly_backend();
    const size_t byte_count = parse_positive(argv[1]);
    const size_t iterations = parse_positive(argv[2]);
    const size_t warmup_iterations = std::stoull(argv[3]);

    auto warmup_input = make_input(byte_count);
    std::array<uint8_t, SHA256_DIGEST_LENGTH> warmup_output{};
    static_cast<void>(run(warmup_input, warmup_output, warmup_iterations));

    auto input = make_input(byte_count);
    std::array<uint8_t, SHA256_DIGEST_LENGTH> output{};
    const auto start = std::chrono::steady_clock::now();
    const uint64_t checksum = run(input, output, iterations);
    const auto end = std::chrono::steady_clock::now();
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
            .count();

    std::cout << "RESULT," << nanoseconds << ',' << checksum << ','
              << hex_string(output) << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
