#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

enum class Operation { kKeyGeneration, kSigning, kVerification };

struct Measurement {
  int64_t nanoseconds;
  uint64_t checksum;
};

uint8_t HexNibble(char value) {
  if (value >= '0' && value <= '9') {
    return static_cast<uint8_t>(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return static_cast<uint8_t>(value - 'a' + 10);
  }
  if (value >= 'A' && value <= 'F') {
    return static_cast<uint8_t>(value - 'A' + 10);
  }
  throw std::runtime_error("invalid hexadecimal input");
}

std::vector<uint8_t> DecodeHex(std::string_view value, size_t byte_count) {
  if (value.size() != byte_count * 2) {
    throw std::runtime_error("invalid hexadecimal input length");
  }
  std::vector<uint8_t> result(byte_count);
  for (size_t index = 0; index < byte_count; index++) {
    result[index] = static_cast<uint8_t>((HexNibble(value[index * 2]) << 4) |
                                         HexNibble(value[index * 2 + 1]));
  }
  return result;
}

std::string EncodeHex(const uint8_t *bytes, size_t byte_count) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string result(byte_count * 2, '\0');
  for (size_t index = 0; index < byte_count; index++) {
    result[index * 2] = kDigits[bytes[index] >> 4];
    result[index * 2 + 1] = kDigits[bytes[index] & 0x0f];
  }
  return result;
}

std::vector<uint8_t> MarshalPublicKey(const MLDSA65_public_key *public_key) {
  CBB builder;
  if (!CBB_init(&builder, MLDSA65_PUBLIC_KEY_BYTES)) {
    throw std::runtime_error("could not initialize public-key builder");
  }
  uint8_t *encoded = nullptr;
  size_t encoded_length = 0;
  if (!MLDSA65_marshal_public_key(&builder, public_key) ||
      !CBB_finish(&builder, &encoded, &encoded_length)) {
    CBB_cleanup(&builder);
    throw std::runtime_error("could not marshal public key");
  }
  std::vector<uint8_t> result(encoded, encoded + encoded_length);
  OPENSSL_free(encoded);
  if (result.size() != MLDSA65_PUBLIC_KEY_BYTES) {
    throw std::runtime_error("marshaled public key has unexpected length");
  }
  return result;
}

MLDSA65_public_key ParsePublicKey(const std::vector<uint8_t> &encoded) {
  CBS input;
  CBS_init(&input, encoded.data(), encoded.size());
  MLDSA65_public_key public_key;
  if (!MLDSA65_parse_public_key(&public_key, &input)) {
    throw std::runtime_error("could not parse public key");
  }
  return public_key;
}

Operation ParseOperation(std::string_view value) {
  if (value == "keygen") {
    return Operation::kKeyGeneration;
  }
  if (value == "sign") {
    return Operation::kSigning;
  }
  if (value == "verify") {
    return Operation::kVerification;
  }
  throw std::runtime_error("invalid operation");
}

Measurement Run(Operation operation, int iterations, int warmup_iterations) {
  std::array<uint8_t, MLDSA65_PUBLIC_KEY_BYTES> encoded_public{};
  std::array<uint8_t, MLDSA_SEED_BYTES> seed{};
  std::array<uint8_t, MLDSA65_SIGNATURE_BYTES> signature{};
  std::array<uint8_t, 1024> message{};
  std::array<uint8_t, 17> context{};
  MLDSA65_private_key private_key;
  MLDSA65_public_key public_key;
  if (!MLDSA65_generate_key(encoded_public.data(), seed.data(), &private_key) ||
      !MLDSA65_public_from_private(&public_key, &private_key) ||
      !MLDSA65_sign(signature.data(), &private_key, message.data(), message.size(),
                    context.data(), context.size())) {
    throw std::runtime_error("ML-DSA setup failed");
  }

  uint64_t checksum = 0;
  const auto execute = [&](int iteration) {
    switch (operation) {
    case Operation::kKeyGeneration:
      if (!MLDSA65_generate_key(encoded_public.data(), seed.data(), &private_key)) {
        throw std::runtime_error("ML-DSA key generation failed");
      }
      checksum += encoded_public[iteration % encoded_public.size()];
      break;
    case Operation::kSigning:
      if (!MLDSA65_sign(signature.data(), &private_key, message.data(),
                        message.size(), context.data(), context.size())) {
        throw std::runtime_error("ML-DSA signing failed");
      }
      checksum += signature[iteration % signature.size()];
      break;
    case Operation::kVerification:
      if (!MLDSA65_verify(&public_key, signature.data(), signature.size(),
                          message.data(), message.size(), context.data(),
                          context.size())) {
        throw std::runtime_error("ML-DSA verification failed");
      }
      checksum += signature[iteration % signature.size()];
      break;
    }
  };
  for (int iteration = 0; iteration < warmup_iterations; iteration++) {
    execute(iteration);
  }
  checksum = 0;
  const auto start = std::chrono::steady_clock::now();
  for (int iteration = 0; iteration < iterations; iteration++) {
    execute(iteration);
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start);
  return {elapsed.count(), checksum};
}

void EmitFixture(const std::vector<uint8_t> &seed,
                 const std::vector<uint8_t> &message,
                 const std::vector<uint8_t> &context) {
  MLDSA65_private_key private_key;
  MLDSA65_public_key public_key;
  std::array<uint8_t, MLDSA65_SIGNATURE_BYTES> signature{};
  if (!MLDSA65_private_key_from_seed(&private_key, seed.data(), seed.size()) ||
      !MLDSA65_public_from_private(&public_key, &private_key) ||
      !MLDSA65_sign(signature.data(), &private_key, message.data(), message.size(),
                    context.data(), context.size())) {
    throw std::runtime_error("could not create BoringSSL fixture");
  }
  const auto encoded_public = MarshalPublicKey(&public_key);
  std::cout << "FIXTURE," << EncodeHex(encoded_public.data(), encoded_public.size())
            << ',' << EncodeHex(signature.data(), signature.size()) << '\n';
}

void ValidateFixture(const std::vector<uint8_t> &seed,
                     const std::vector<uint8_t> &expected_public,
                     const std::vector<uint8_t> &signature,
                     const std::vector<uint8_t> &message,
                     const std::vector<uint8_t> &context) {
  MLDSA65_private_key private_key;
  MLDSA65_public_key derived_public;
  if (!MLDSA65_private_key_from_seed(&private_key, seed.data(), seed.size()) ||
      !MLDSA65_public_from_private(&derived_public, &private_key)) {
    throw std::runtime_error("could not derive BoringSSL key");
  }
  if (MarshalPublicKey(&derived_public) != expected_public) {
    throw std::runtime_error("public key mismatch");
  }
  const MLDSA65_public_key parsed_public = ParsePublicKey(expected_public);
  if (!MLDSA65_verify(&parsed_public, signature.data(), signature.size(),
                      message.data(), message.size(), context.data(),
                      context.size())) {
    throw std::runtime_error("SwiftSSL signature did not verify");
  }
  std::cout << "VALIDATED\n";
}

void VerifyFixture(const std::vector<uint8_t> &encoded_public,
                   const std::vector<uint8_t> &signature,
                   const std::vector<uint8_t> &message,
                   const std::vector<uint8_t> &context) {
  const MLDSA65_public_key public_key = ParsePublicKey(encoded_public);
  const int valid = MLDSA65_verify(
      &public_key, signature.data(), signature.size(), message.data(),
      message.size(), context.data(), context.size());
  std::cout << "VERIFIED," << valid << '\n';
}

}  // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--capabilities") {
      std::cout << "CAPABILITY,boringssl_asm," << CRYPTO_has_asm() << '\n';
      return 0;
    }
    if (argc == 4 && argv[1][0] != '-') {
      const int iterations = std::stoi(argv[2]);
      const int warmup_iterations = std::stoi(argv[3]);
      if (iterations <= 0 || warmup_iterations < 0) {
        throw std::runtime_error("invalid iteration count");
      }
      const Measurement measurement =
          Run(ParseOperation(argv[1]), iterations, warmup_iterations);
      std::cout << "RESULT," << measurement.nanoseconds << ','
                << measurement.checksum << '\n';
      return 0;
    }
    if (argc == 5 && std::string_view(argv[1]) == "--fixture") {
      EmitFixture(DecodeHex(argv[2], MLDSA_SEED_BYTES),
                  DecodeHex(argv[3], 64), DecodeHex(argv[4], 19));
      return 0;
    }
    if (argc == 7 && std::string_view(argv[1]) == "--validate") {
      ValidateFixture(DecodeHex(argv[2], MLDSA_SEED_BYTES),
                      DecodeHex(argv[3], MLDSA65_PUBLIC_KEY_BYTES),
                      DecodeHex(argv[4], MLDSA65_SIGNATURE_BYTES),
                      DecodeHex(argv[5], 64), DecodeHex(argv[6], 19));
      return 0;
    }
    if (argc == 6 && std::string_view(argv[1]) == "--verify") {
      VerifyFixture(DecodeHex(argv[2], MLDSA65_PUBLIC_KEY_BYTES),
                    DecodeHex(argv[3], MLDSA65_SIGNATURE_BYTES),
                    DecodeHex(argv[4], 64), DecodeHex(argv[5], 19));
      return 0;
    }
    throw std::runtime_error("invalid arguments");
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
