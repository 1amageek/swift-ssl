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

template <int ParameterSet>
struct MLDSATraits;

#define DEFINE_MLDSA_TRAITS(PARAMETER_SET)                                    \
  template <>                                                                 \
  struct MLDSATraits<PARAMETER_SET> {                                         \
    using PrivateKey = MLDSA##PARAMETER_SET##_private_key;                    \
    using PublicKey = MLDSA##PARAMETER_SET##_public_key;                      \
    static constexpr size_t kPublicKeyBytes =                                 \
        MLDSA##PARAMETER_SET##_PUBLIC_KEY_BYTES;                              \
    static constexpr size_t kSignatureBytes =                                 \
        MLDSA##PARAMETER_SET##_SIGNATURE_BYTES;                               \
    static int Generate(uint8_t *encoded_public, uint8_t *seed,               \
                        PrivateKey *private_key) {                            \
      return MLDSA##PARAMETER_SET##_generate_key(encoded_public, seed,        \
                                                  private_key);               \
    }                                                                         \
    static int PrivateFromSeed(PrivateKey *private_key, const uint8_t *seed,  \
                               size_t seed_length) {                          \
      return MLDSA##PARAMETER_SET##_private_key_from_seed(                    \
          private_key, seed, seed_length);                                    \
    }                                                                         \
    static int PublicFromPrivate(PublicKey *public_key,                       \
                                 const PrivateKey *private_key) {             \
      return MLDSA##PARAMETER_SET##_public_from_private(public_key,           \
                                                         private_key);        \
    }                                                                         \
    static int Sign(uint8_t *signature, const PrivateKey *private_key,        \
                    const uint8_t *message, size_t message_length,            \
                    const uint8_t *context, size_t context_length) {          \
      return MLDSA##PARAMETER_SET##_sign(                                     \
          signature, private_key, message, message_length, context,           \
          context_length);                                                    \
    }                                                                         \
    static int Verify(const PublicKey *public_key, const uint8_t *signature,  \
                      size_t signature_length, const uint8_t *message,        \
                      size_t message_length, const uint8_t *context,          \
                      size_t context_length) {                                \
      return MLDSA##PARAMETER_SET##_verify(                                   \
          public_key, signature, signature_length, message, message_length,   \
          context, context_length);                                           \
    }                                                                         \
    static int Marshal(CBB *builder, const PublicKey *public_key) {           \
      return MLDSA##PARAMETER_SET##_marshal_public_key(builder, public_key);  \
    }                                                                         \
    static int Parse(PublicKey *public_key, CBS *input) {                     \
      return MLDSA##PARAMETER_SET##_parse_public_key(public_key, input);      \
    }                                                                         \
  }

DEFINE_MLDSA_TRAITS(44);
DEFINE_MLDSA_TRAITS(65);
DEFINE_MLDSA_TRAITS(87);

#undef DEFINE_MLDSA_TRAITS

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

template <typename Traits>
std::vector<uint8_t> MarshalPublicKey(
    const typename Traits::PublicKey *public_key) {
  CBB builder;
  if (!CBB_init(&builder, Traits::kPublicKeyBytes)) {
    throw std::runtime_error("could not initialize public-key builder");
  }
  uint8_t *encoded = nullptr;
  size_t encoded_length = 0;
  if (!Traits::Marshal(&builder, public_key) ||
      !CBB_finish(&builder, &encoded, &encoded_length)) {
    CBB_cleanup(&builder);
    throw std::runtime_error("could not marshal public key");
  }
  std::vector<uint8_t> result(encoded, encoded + encoded_length);
  OPENSSL_free(encoded);
  if (result.size() != Traits::kPublicKeyBytes) {
    throw std::runtime_error("marshaled public key has unexpected length");
  }
  return result;
}

template <typename Traits>
typename Traits::PublicKey ParsePublicKey(const std::vector<uint8_t> &encoded) {
  CBS input;
  CBS_init(&input, encoded.data(), encoded.size());
  typename Traits::PublicKey public_key;
  if (!Traits::Parse(&public_key, &input) || CBS_len(&input) != 0) {
    throw std::runtime_error("could not parse public key");
  }
  return public_key;
}

int ParseParameterSet(std::string_view value) {
  if (value == "44") {
    return 44;
  }
  if (value == "65") {
    return 65;
  }
  if (value == "87") {
    return 87;
  }
  throw std::runtime_error("invalid parameter set");
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

template <typename Traits>
Measurement Run(Operation operation, int iterations, int warmup_iterations) {
  std::array<uint8_t, Traits::kPublicKeyBytes> encoded_public{};
  std::array<uint8_t, MLDSA_SEED_BYTES> seed{};
  std::array<uint8_t, Traits::kSignatureBytes> signature{};
  std::array<uint8_t, 1024> message{};
  std::array<uint8_t, 17> context{};
  typename Traits::PrivateKey private_key;
  typename Traits::PublicKey public_key;
  if (!Traits::Generate(encoded_public.data(), seed.data(), &private_key) ||
      !Traits::PublicFromPrivate(&public_key, &private_key) ||
      !Traits::Sign(signature.data(), &private_key, message.data(),
                    message.size(), context.data(), context.size())) {
    throw std::runtime_error("ML-DSA setup failed");
  }

  uint64_t checksum = 0;
  const auto execute = [&](int iteration) {
    switch (operation) {
    case Operation::kKeyGeneration:
      if (!Traits::Generate(encoded_public.data(), seed.data(), &private_key)) {
        throw std::runtime_error("ML-DSA key generation failed");
      }
      checksum += encoded_public[iteration % encoded_public.size()];
      break;
    case Operation::kSigning:
      if (!Traits::Sign(signature.data(), &private_key, message.data(),
                        message.size(), context.data(), context.size())) {
        throw std::runtime_error("ML-DSA signing failed");
      }
      checksum += signature[iteration % signature.size()];
      break;
    case Operation::kVerification:
      if (!Traits::Verify(&public_key, signature.data(), signature.size(),
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

Measurement Run(int parameter_set, Operation operation, int iterations,
                int warmup_iterations) {
  switch (parameter_set) {
  case 44:
    return Run<MLDSATraits<44>>(operation, iterations, warmup_iterations);
  case 65:
    return Run<MLDSATraits<65>>(operation, iterations, warmup_iterations);
  case 87:
    return Run<MLDSATraits<87>>(operation, iterations, warmup_iterations);
  default:
    throw std::runtime_error("invalid parameter set");
  }
}

template <typename Traits>
void EmitFixture(const std::vector<uint8_t> &seed,
                 const std::vector<uint8_t> &message,
                 const std::vector<uint8_t> &context) {
  typename Traits::PrivateKey private_key;
  typename Traits::PublicKey public_key;
  std::array<uint8_t, Traits::kSignatureBytes> signature{};
  if (!Traits::PrivateFromSeed(&private_key, seed.data(), seed.size()) ||
      !Traits::PublicFromPrivate(&public_key, &private_key) ||
      !Traits::Sign(signature.data(), &private_key, message.data(),
                    message.size(), context.data(), context.size())) {
    throw std::runtime_error("could not create BoringSSL fixture");
  }
  const auto encoded_public = MarshalPublicKey<Traits>(&public_key);
  std::cout << "FIXTURE," << EncodeHex(encoded_public.data(), encoded_public.size())
            << ',' << EncodeHex(signature.data(), signature.size()) << '\n';
}

template <typename Traits>
void ValidateFixture(const std::vector<uint8_t> &seed,
                     const std::vector<uint8_t> &expected_public,
                     const std::vector<uint8_t> &signature,
                     const std::vector<uint8_t> &message,
                     const std::vector<uint8_t> &context) {
  typename Traits::PrivateKey private_key;
  typename Traits::PublicKey derived_public;
  if (!Traits::PrivateFromSeed(&private_key, seed.data(), seed.size()) ||
      !Traits::PublicFromPrivate(&derived_public, &private_key)) {
    throw std::runtime_error("could not derive BoringSSL key");
  }
  if (MarshalPublicKey<Traits>(&derived_public) != expected_public) {
    throw std::runtime_error("public key mismatch");
  }
  const typename Traits::PublicKey parsed_public =
      ParsePublicKey<Traits>(expected_public);
  if (!Traits::Verify(&parsed_public, signature.data(), signature.size(),
                      message.data(), message.size(), context.data(),
                      context.size())) {
    throw std::runtime_error("SSL signature did not verify");
  }
  std::cout << "VALIDATED\n";
}

template <typename Traits>
void VerifyFixture(const std::vector<uint8_t> &encoded_public,
                   const std::vector<uint8_t> &signature,
                   const std::vector<uint8_t> &message,
                   const std::vector<uint8_t> &context) {
  const typename Traits::PublicKey public_key =
      ParsePublicKey<Traits>(encoded_public);
  const int valid = Traits::Verify(
      &public_key, signature.data(), signature.size(), message.data(),
      message.size(), context.data(), context.size());
  std::cout << "VERIFIED," << valid << '\n';
}

void EmitFixture(int parameter_set, const std::vector<uint8_t> &seed,
                 const std::vector<uint8_t> &message,
                 const std::vector<uint8_t> &context) {
  switch (parameter_set) {
  case 44:
    return EmitFixture<MLDSATraits<44>>(seed, message, context);
  case 65:
    return EmitFixture<MLDSATraits<65>>(seed, message, context);
  case 87:
    return EmitFixture<MLDSATraits<87>>(seed, message, context);
  default:
    throw std::runtime_error("invalid parameter set");
  }
}

void ValidateFixture(int parameter_set, const std::vector<uint8_t> &seed,
                     const std::vector<uint8_t> &expected_public,
                     const std::vector<uint8_t> &signature,
                     const std::vector<uint8_t> &message,
                     const std::vector<uint8_t> &context) {
  switch (parameter_set) {
  case 44:
    return ValidateFixture<MLDSATraits<44>>(seed, expected_public, signature,
                                            message, context);
  case 65:
    return ValidateFixture<MLDSATraits<65>>(seed, expected_public, signature,
                                            message, context);
  case 87:
    return ValidateFixture<MLDSATraits<87>>(seed, expected_public, signature,
                                            message, context);
  default:
    throw std::runtime_error("invalid parameter set");
  }
}

void VerifyFixture(int parameter_set,
                   const std::vector<uint8_t> &encoded_public,
                   const std::vector<uint8_t> &signature,
                   const std::vector<uint8_t> &message,
                   const std::vector<uint8_t> &context) {
  switch (parameter_set) {
  case 44:
    return VerifyFixture<MLDSATraits<44>>(encoded_public, signature, message,
                                          context);
  case 65:
    return VerifyFixture<MLDSATraits<65>>(encoded_public, signature, message,
                                          context);
  case 87:
    return VerifyFixture<MLDSATraits<87>>(encoded_public, signature, message,
                                          context);
  default:
    throw std::runtime_error("invalid parameter set");
  }
}

size_t PublicKeyBytes(int parameter_set) {
  switch (parameter_set) {
  case 44:
    return MLDSATraits<44>::kPublicKeyBytes;
  case 65:
    return MLDSATraits<65>::kPublicKeyBytes;
  case 87:
    return MLDSATraits<87>::kPublicKeyBytes;
  default:
    throw std::runtime_error("invalid parameter set");
  }
}

size_t SignatureBytes(int parameter_set) {
  switch (parameter_set) {
  case 44:
    return MLDSATraits<44>::kSignatureBytes;
  case 65:
    return MLDSATraits<65>::kSignatureBytes;
  case 87:
    return MLDSATraits<87>::kSignatureBytes;
  default:
    throw std::runtime_error("invalid parameter set");
  }
}

}  // namespace

int main(int argc, char **argv) {
  try {
    if (argc == 2 && std::string_view(argv[1]) == "--capabilities") {
      std::cout << "CAPABILITY,boringssl_asm," << CRYPTO_has_asm() << '\n';
      return 0;
    }
    if (argc == 5 && argv[1][0] != '-') {
      const int parameter_set = ParseParameterSet(argv[1]);
      const int iterations = std::stoi(argv[3]);
      const int warmup_iterations = std::stoi(argv[4]);
      if (iterations <= 0 || warmup_iterations < 0) {
        throw std::runtime_error("invalid iteration count");
      }
      const Measurement measurement =
          Run(parameter_set, ParseOperation(argv[2]), iterations,
              warmup_iterations);
      std::cout << "RESULT," << measurement.nanoseconds << ','
                << measurement.checksum << '\n';
      return 0;
    }
    if (argc == 6 && std::string_view(argv[1]) == "--fixture") {
      const int parameter_set = ParseParameterSet(argv[2]);
      EmitFixture(parameter_set, DecodeHex(argv[3], MLDSA_SEED_BYTES),
                  DecodeHex(argv[4], 64), DecodeHex(argv[5], 19));
      return 0;
    }
    if (argc == 8 && std::string_view(argv[1]) == "--validate") {
      const int parameter_set = ParseParameterSet(argv[2]);
      ValidateFixture(parameter_set,
                      DecodeHex(argv[3], MLDSA_SEED_BYTES),
                      DecodeHex(argv[4], PublicKeyBytes(parameter_set)),
                      DecodeHex(argv[5], SignatureBytes(parameter_set)),
                      DecodeHex(argv[6], 64), DecodeHex(argv[7], 19));
      return 0;
    }
    if (argc == 7 && std::string_view(argv[1]) == "--verify") {
      const int parameter_set = ParseParameterSet(argv[2]);
      VerifyFixture(parameter_set,
                    DecodeHex(argv[3], PublicKeyBytes(parameter_set)),
                    DecodeHex(argv[4], SignatureBytes(parameter_set)),
                    DecodeHex(argv[5], 64), DecodeHex(argv[6], 19));
      return 0;
    }
    throw std::runtime_error("invalid arguments");
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
