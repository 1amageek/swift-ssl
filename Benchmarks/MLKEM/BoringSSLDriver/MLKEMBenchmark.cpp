#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

enum class Operation { kKeyGeneration, kEncapsulation, kDecapsulation };

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

template <typename PublicKey>
std::vector<uint8_t> MarshalPublicKey(const PublicKey *public_key,
                                      int (*marshal)(CBB *, const PublicKey *),
                                      size_t expected_byte_count) {
  CBB builder;
  if (!CBB_init(&builder, expected_byte_count)) {
    throw std::runtime_error("could not initialize public-key builder");
  }
  uint8_t *encoded = nullptr;
  size_t encoded_length = 0;
  if (!marshal(&builder, public_key) ||
      !CBB_finish(&builder, &encoded, &encoded_length)) {
    CBB_cleanup(&builder);
    throw std::runtime_error("could not marshal public key");
  }
  std::vector<uint8_t> result(encoded, encoded + encoded_length);
  OPENSSL_free(encoded);
  if (result.size() != expected_byte_count) {
    throw std::runtime_error("marshaled public key has unexpected length");
  }
  return result;
}

Operation ParseOperation(std::string_view value) {
  if (value == "keygen") {
    return Operation::kKeyGeneration;
  }
  if (value == "encap") {
    return Operation::kEncapsulation;
  }
  if (value == "decap") {
    return Operation::kDecapsulation;
  }
  throw std::runtime_error("invalid operation");
}

Measurement Run768(Operation operation, int iterations) {
  uint8_t encoded_public[MLKEM768_PUBLIC_KEY_BYTES];
  MLKEM768_private_key private_key;
  MLKEM768_public_key public_key;
  uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  MLKEM768_generate_key(encoded_public, nullptr, &private_key);
  MLKEM768_public_from_private(&public_key, &private_key);
  MLKEM768_encap(ciphertext, shared_secret, &public_key);

  const auto start = std::chrono::steady_clock::now();
  uint64_t checksum = 0;
  for (int iteration = 0; iteration < iterations; iteration++) {
    switch (operation) {
    case Operation::kKeyGeneration:
      MLKEM768_generate_key(encoded_public, nullptr, &private_key);
      checksum += encoded_public[iteration % MLKEM768_PUBLIC_KEY_BYTES];
      break;
    case Operation::kEncapsulation:
      MLKEM768_encap(ciphertext, shared_secret, &public_key);
      checksum += ciphertext[iteration % MLKEM768_CIPHERTEXT_BYTES];
      checksum += shared_secret[iteration % MLKEM_SHARED_SECRET_BYTES];
      break;
    case Operation::kDecapsulation:
      if (!MLKEM768_decap(shared_secret, ciphertext, sizeof(ciphertext),
                          &private_key)) {
        throw std::runtime_error("ML-KEM-768 decapsulation failed");
      }
      checksum += shared_secret[iteration % MLKEM_SHARED_SECRET_BYTES];
      break;
    }
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start);
  return {elapsed.count(), checksum};
}

Measurement Run1024(Operation operation, int iterations) {
  uint8_t encoded_public[MLKEM1024_PUBLIC_KEY_BYTES];
  MLKEM1024_private_key private_key;
  MLKEM1024_public_key public_key;
  uint8_t ciphertext[MLKEM1024_CIPHERTEXT_BYTES];
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  MLKEM1024_generate_key(encoded_public, nullptr, &private_key);
  MLKEM1024_public_from_private(&public_key, &private_key);
  MLKEM1024_encap(ciphertext, shared_secret, &public_key);

  const auto start = std::chrono::steady_clock::now();
  uint64_t checksum = 0;
  for (int iteration = 0; iteration < iterations; iteration++) {
    switch (operation) {
    case Operation::kKeyGeneration:
      MLKEM1024_generate_key(encoded_public, nullptr, &private_key);
      checksum += encoded_public[iteration % MLKEM1024_PUBLIC_KEY_BYTES];
      break;
    case Operation::kEncapsulation:
      MLKEM1024_encap(ciphertext, shared_secret, &public_key);
      checksum += ciphertext[iteration % MLKEM1024_CIPHERTEXT_BYTES];
      checksum += shared_secret[iteration % MLKEM_SHARED_SECRET_BYTES];
      break;
    case Operation::kDecapsulation:
      if (!MLKEM1024_decap(shared_secret, ciphertext, sizeof(ciphertext),
                           &private_key)) {
        throw std::runtime_error("ML-KEM-1024 decapsulation failed");
      }
      checksum += shared_secret[iteration % MLKEM_SHARED_SECRET_BYTES];
      break;
    }
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start);
  return {elapsed.count(), checksum};
}

Measurement Run(int parameters, Operation operation, int iterations) {
  if (parameters == 768) {
    return Run768(operation, iterations);
  }
  if (parameters == 1024) {
    return Run1024(operation, iterations);
  }
  throw std::runtime_error("invalid parameter set");
}

void EmitFixture768(const std::vector<uint8_t> &seed) {
  MLKEM768_private_key private_key;
  MLKEM768_public_key public_key;
  if (!MLKEM768_private_key_from_seed(&private_key, seed.data(), seed.size())) {
    throw std::runtime_error("ML-KEM-768 seed was rejected");
  }
  MLKEM768_public_from_private(&public_key, &private_key);
  const std::vector<uint8_t> encoded_public = MarshalPublicKey(
      &public_key, MLKEM768_marshal_public_key, MLKEM768_PUBLIC_KEY_BYTES);
  uint8_t ciphertext[MLKEM768_CIPHERTEXT_BYTES];
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  MLKEM768_encap(ciphertext, shared_secret, &public_key);
  std::cout << "FIXTURE,"
            << EncodeHex(encoded_public.data(), encoded_public.size()) << ','
            << EncodeHex(ciphertext, sizeof(ciphertext)) << ','
            << EncodeHex(shared_secret, sizeof(shared_secret)) << '\n';
}

void EmitFixture1024(const std::vector<uint8_t> &seed) {
  MLKEM1024_private_key private_key;
  MLKEM1024_public_key public_key;
  if (!MLKEM1024_private_key_from_seed(&private_key, seed.data(),
                                       seed.size())) {
    throw std::runtime_error("ML-KEM-1024 seed was rejected");
  }
  MLKEM1024_public_from_private(&public_key, &private_key);
  const std::vector<uint8_t> encoded_public = MarshalPublicKey(
      &public_key, MLKEM1024_marshal_public_key, MLKEM1024_PUBLIC_KEY_BYTES);
  uint8_t ciphertext[MLKEM1024_CIPHERTEXT_BYTES];
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  MLKEM1024_encap(ciphertext, shared_secret, &public_key);
  std::cout << "FIXTURE,"
            << EncodeHex(encoded_public.data(), encoded_public.size()) << ','
            << EncodeHex(ciphertext, sizeof(ciphertext)) << ','
            << EncodeHex(shared_secret, sizeof(shared_secret)) << '\n';
}

void ValidateFixture768(const std::vector<uint8_t> &seed,
                        const std::vector<uint8_t> &expected_public,
                        const std::vector<uint8_t> &ciphertext,
                        const std::vector<uint8_t> &expected_secret) {
  MLKEM768_private_key private_key;
  MLKEM768_public_key public_key;
  if (!MLKEM768_private_key_from_seed(&private_key, seed.data(), seed.size())) {
    throw std::runtime_error("ML-KEM-768 seed was rejected");
  }
  MLKEM768_public_from_private(&public_key, &private_key);
  const std::vector<uint8_t> encoded_public = MarshalPublicKey(
      &public_key, MLKEM768_marshal_public_key, MLKEM768_PUBLIC_KEY_BYTES);
  if (encoded_public != expected_public) {
    throw std::runtime_error("ML-KEM-768 public key mismatch");
  }
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  if (!MLKEM768_decap(shared_secret, ciphertext.data(), ciphertext.size(),
                      &private_key) ||
      !std::equal(std::begin(shared_secret), std::end(shared_secret),
                  expected_secret.begin(), expected_secret.end())) {
    throw std::runtime_error("ML-KEM-768 shared secret mismatch");
  }
}

void ValidateFixture1024(const std::vector<uint8_t> &seed,
                         const std::vector<uint8_t> &expected_public,
                         const std::vector<uint8_t> &ciphertext,
                         const std::vector<uint8_t> &expected_secret) {
  MLKEM1024_private_key private_key;
  MLKEM1024_public_key public_key;
  if (!MLKEM1024_private_key_from_seed(&private_key, seed.data(),
                                       seed.size())) {
    throw std::runtime_error("ML-KEM-1024 seed was rejected");
  }
  MLKEM1024_public_from_private(&public_key, &private_key);
  const std::vector<uint8_t> encoded_public = MarshalPublicKey(
      &public_key, MLKEM1024_marshal_public_key, MLKEM1024_PUBLIC_KEY_BYTES);
  if (encoded_public != expected_public) {
    throw std::runtime_error("ML-KEM-1024 public key mismatch");
  }
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  if (!MLKEM1024_decap(shared_secret, ciphertext.data(), ciphertext.size(),
                       &private_key) ||
      !std::equal(std::begin(shared_secret), std::end(shared_secret),
                  expected_secret.begin(), expected_secret.end())) {
    throw std::runtime_error("ML-KEM-1024 shared secret mismatch");
  }
}

std::string Decapsulate768(const std::vector<uint8_t> &seed,
                           const std::vector<uint8_t> &ciphertext) {
  MLKEM768_private_key private_key;
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  if (!MLKEM768_private_key_from_seed(&private_key, seed.data(), seed.size()) ||
      !MLKEM768_decap(shared_secret, ciphertext.data(), ciphertext.size(),
                      &private_key)) {
    throw std::runtime_error("ML-KEM-768 decapsulation failed");
  }
  return EncodeHex(shared_secret, sizeof(shared_secret));
}

std::string Decapsulate1024(const std::vector<uint8_t> &seed,
                            const std::vector<uint8_t> &ciphertext) {
  MLKEM1024_private_key private_key;
  uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
  if (!MLKEM1024_private_key_from_seed(&private_key, seed.data(),
                                       seed.size()) ||
      !MLKEM1024_decap(shared_secret, ciphertext.data(), ciphertext.size(),
                       &private_key)) {
    throw std::runtime_error("ML-KEM-1024 decapsulation failed");
  }
  return EncodeHex(shared_secret, sizeof(shared_secret));
}

int RunValidationCommand(int argc, char **argv) {
  if (argc < 4) {
    throw std::runtime_error("invalid validation command");
  }
  const int parameters = std::stoi(argv[2]);
  const std::vector<uint8_t> seed = DecodeHex(argv[3], MLKEM_SEED_BYTES);
  if (std::string_view(argv[1]) == "--fixture" && argc == 4) {
    if (parameters == 768) {
      EmitFixture768(seed);
    } else if (parameters == 1024) {
      EmitFixture1024(seed);
    } else {
      throw std::runtime_error("invalid parameter set");
    }
    return 0;
  }
  if (std::string_view(argv[1]) == "--validate" && argc == 7) {
    const size_t public_byte_count = parameters == 768
                                         ? MLKEM768_PUBLIC_KEY_BYTES
                                         : MLKEM1024_PUBLIC_KEY_BYTES;
    const size_t ciphertext_byte_count = parameters == 768
                                             ? MLKEM768_CIPHERTEXT_BYTES
                                             : MLKEM1024_CIPHERTEXT_BYTES;
    const std::vector<uint8_t> public_key =
        DecodeHex(argv[4], public_byte_count);
    const std::vector<uint8_t> ciphertext =
        DecodeHex(argv[5], ciphertext_byte_count);
    const std::vector<uint8_t> shared_secret =
        DecodeHex(argv[6], MLKEM_SHARED_SECRET_BYTES);
    if (parameters == 768) {
      ValidateFixture768(seed, public_key, ciphertext, shared_secret);
    } else if (parameters == 1024) {
      ValidateFixture1024(seed, public_key, ciphertext, shared_secret);
    } else {
      throw std::runtime_error("invalid parameter set");
    }
    std::cout << "VALIDATED\n";
    return 0;
  }
  if (std::string_view(argv[1]) == "--decap" && argc == 5) {
    if (parameters == 768) {
      const std::vector<uint8_t> ciphertext =
          DecodeHex(argv[4], MLKEM768_CIPHERTEXT_BYTES);
      std::cout << "SECRET," << Decapsulate768(seed, ciphertext) << '\n';
    } else if (parameters == 1024) {
      const std::vector<uint8_t> ciphertext =
          DecodeHex(argv[4], MLKEM1024_CIPHERTEXT_BYTES);
      std::cout << "SECRET," << Decapsulate1024(seed, ciphertext) << '\n';
    } else {
      throw std::runtime_error("invalid parameter set");
    }
    return 0;
  }
  throw std::runtime_error("invalid validation command");
}

} // namespace

int main(int argc, char **argv) {
  if (argc == 2 && std::string_view(argv[1]) == "--capabilities") {
    std::cout << "CAPABILITY,boringssl_asm," << CRYPTO_has_asm() << '\n';
    return 0;
  }
  if (argc > 1 && std::string_view(argv[1]).substr(0, 2) == "--") {
    try {
      return RunValidationCommand(argc, argv);
    } catch (const std::exception &error) {
      std::cerr << error.what() << '\n';
      return 1;
    }
  }
  if (argc != 5) {
    std::cerr << "usage: boringssl-mlkem-benchmark <768|1024> "
                 "<keygen|encap|decap> <iterations> <warmup-iterations>\n";
    return 2;
  }

  try {
    const int parameters = std::stoi(argv[1]);
    const Operation operation = ParseOperation(argv[2]);
    const int iterations = std::stoi(argv[3]);
    const int warmup_iterations = std::stoi(argv[4]);
    if (iterations <= 0 || warmup_iterations < 0) {
      throw std::runtime_error("invalid iteration count");
    }

    Run(parameters, operation, warmup_iterations);
    const Measurement measurement = Run(parameters, operation, iterations);
    std::cout << "RESULT," << measurement.nanoseconds << ','
              << measurement.checksum << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
